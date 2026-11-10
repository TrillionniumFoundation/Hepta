"""Author the complete effects/resources source subgrammars in executable HIA.

The host authoring helper is retained explicitly. Grammar, duplicate-key
recognition, bounded measurement, and transactional arena publication execute
in the resulting HIA program; constructing Python values remains a bridge.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_source_lexer import source_program as lexer_program, KEYWORD_ORDER

MAGIC = 5208780291424916339
WORKSPACE_HEADER = 384
SOURCE = r'''
def clauses_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 384 or length(s) > 8388608:
        return 4294967293
    mode = get(w, 208)
    command = get(w, 224)
    if (mode != 1 and mode != 2) or command > 1:
        return 4294967293
    slots = 0
    if command == 1:
        if ((length(w) - 384) & 15) != 0:
            return 4294967293
        slots = (length(w) - 384) >> 4
        if slots < 2 or (slots & (slots - 1)) != 0:
            return 4294967293
        i = 384
        while i < length(w):
            put(w, i, 0)
            i = i + 8
    clauses_reset(w, 0, slots)
    clauses_parse(s, o, w, mode)
    if get(w, 48) != 0 or get(w, 216) != 0:
        return 4294967295
    count = get(w, 200)
    used = 64 + count * 40
    if command == 0:
        return used
    if used > length(o):
        return 4294967294
    clauses_reset(w, 1, 0)
    clauses_parse(s, o, w, mode)
    put(o, 0, @MAGIC@)
    put(o, 8, 1)
    put(o, 16, mode)
    put(o, 24, count)
    put(o, 32, used)
    put(o, 40, get(w, 184))
    put(o, 48, get(w, 192))
    put(o, 56, 0)
    return used

def clauses_reset(w:mutbuf, phase:u64, slots:u64) -> u64:
    initialize(w, 0)
    put(w, 184, 0)
    put(w, 192, 0)
    put(w, 200, 0)
    put(w, 216, 0)
    put(w, 232, slots)
    put(w, 240, phase)
    put(w, 248, 0)
    return 0

def clauses_next(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    put(w, 40, 0)
    scan_next(s, o, w)
    return 0

def clauses_consume(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    put(w, 184, get(w, 160))
    put(w, 192, get(w, 144))
    clauses_next(s, o, w)
    return 0

def clauses_error(w:mutbuf, code:u64) -> u64:
    if get(w, 216) == 0 and get(w, 48) == 0:
        put(w, 216, code)
        put(w, 304, get(w, 152))
        put(w, 312, get(w, 160))
        put(w, 320, get(w, 168))
        put(w, 328, get(w, 176))
        put(w, 336, get(w, 136))
        put(w, 344, get(w, 144))
    return 0

def clauses_expect(s:readbuf, o:mutbuf, w:mutbuf, kind:u64, code:u64) -> u64:
    if get(w, 216) != 0 or get(w, 48) != 0:
        return 0
    if get(w, 128) != kind:
        return clauses_error(w, code)
    return clauses_consume(s, o, w)

def clauses_same(s:readbuf, begin:u64, end:u64, prior:u64, finish:u64) -> u64:
    if end - begin != finish - prior:
        return 0
    i = 0
    while i < end - begin:
        if byte(s, begin + i) != byte(s, prior + i):
            return 0
        i = i + 1
    return 1

def clauses_unique(s:readbuf, w:mutbuf, code:u64) -> u64:
    slots = get(w, 232)
    if slots == 0:
        return 0
    if get(w, 200) >= 1048576:
        return clauses_error(w, 14)
    if get(w, 200) >= (slots >> 1):
        return clauses_error(w, 13)
    begin = get(w, 136)
    end = get(w, 144)
    hash = 14695981039346656037
    i = begin
    while i < end:
        hash = (hash ^ byte(s, i)) * 1099511628211
        i = i + 1
    slot = hash & (slots - 1)
    probes = 0
    while probes < slots:
        at = 384 + slot * 16
        prior = get(w, at)
        if prior == 0:
            put(w, at, begin + 1)
            put(w, at + 8, end)
            return 0
        if clauses_same(s, begin, end, prior - 1, get(w, at + 8)) != 0:
            return clauses_error(w, code)
        slot = (slot + 1) & (slots - 1)
        probes = probes + 1
    return clauses_error(w, 13)

def clauses_record(o:mutbuf, w:mutbuf, begin:u64, end:u64, kind:u64, value_begin:u64, value_end:u64) -> u64:
    count = get(w, 200)
    if count >= 1048576:
        return clauses_error(w, 14)
    if get(w, 240) == 1:
        at = 64 + count * 40
        put(o, at, begin)
        put(o, at + 8, end)
        put(o, at + 16, kind)
        put(o, at + 24, value_begin)
        put(o, at + 32, value_end)
    put(w, 200, count + 1)
    return 0

def clauses_parse(s:readbuf, o:mutbuf, w:mutbuf, mode:u64) -> u64:
    clauses_next(s, o, w)
    clauses_expect(s, o, w, choose(mode == 1, @EFFECTS@, @RESOURCES@), choose(mode == 1, 1, 6))
    clauses_expect(s, o, w, 379, 2)
    while get(w, 128) != 381 and get(w, 216) == 0 and get(w, 48) == 0:
        kind = get(w, 128)
        if kind != 1 and (mode != 1 or kind != @UNSAFE@):
            return clauses_error(w, choose(mode == 1, 3, 7))
        name_begin = get(w, 136)
        name_end = get(w, 144)
        clauses_unique(s, w, choose(mode == 1, 4, 8))
        clauses_consume(s, o, w)
        if get(w, 216) != 0 or get(w, 48) != 0:
            return 0
        if mode == 1:
            clauses_record(o, w, name_begin, name_end, 0, 0, 0)
            if get(w, 128) != 300:
                clauses_expect(s, o, w, 381, 5)
                return 0
            clauses_consume(s, o, w)
        else:
            clauses_expect(s, o, w, 317, 9)
            if get(w, 216) != 0 or get(w, 48) != 0:
                return 0
            kind = get(w, 128)
            value_kind = 0
            if kind == 3:
                value_kind = 1
            elif kind == 4:
                value_kind = 2
            elif kind == @FALSE@:
                value_kind = 3
            elif kind == @TRUE@:
                value_kind = 4
            else:
                return clauses_error(w, 10)
            clauses_record(o, w, name_begin, name_end, value_kind, get(w, 136), get(w, 144))
            clauses_consume(s, o, w)
            clauses_expect(s, o, w, 315, 11)
    clauses_expect(s, o, w, 381, choose(mode == 1, 5, 12))
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
    for word in ('effects', 'resources', 'unsafe', 'false', 'true'):
        source = source.replace('@' + word.upper() + '@', str(128 + KEYWORD_ORDER.index(word)))
    original = lexer_program()
    definitions = {node.name: node for node in ast.parse(original).body}
    # Include only the scanner's actual dependency closure. Integer/float
    # magnitudes are decoded by the separately bound real native lexer.
    required, pending = set(), ['scan']
    while pending:
        name = pending.pop()
        if name == 'token' or name in required or name not in definitions:
            continue
        required.add(name)
        pending.extend(node.func.id for node in ast.walk(definitions[name])
                       if isinstance(node, ast.Call) and isinstance(node.func, ast.Name))
    required.add('initialize')
    for name, node in definitions.items():
        if name not in required:
            continue
        text = ast.get_source_segment(original, node)
        if name == 'scan':
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
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'source_clauses', 'functions': functions})


def main():
    path = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/source_clauses.hiaasm'
    path.write_text(render_assembly(document()))
    print(path.name, path.stat().st_size)


if __name__ == '__main__':
    main()
