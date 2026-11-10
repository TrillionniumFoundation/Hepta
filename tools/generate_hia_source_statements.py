"""Author the complete existing block/statement grammar as executable HIA.

Composes the actual expression/type/scanner authoring definitions. Explicit
frames implement blocks and match arms; no foreign statement recognizer runs.
Declarations, checker, modules and orchestration remain outside this application.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_source_expressions import source_program as expression_program, token_kind

MAGIC = int.from_bytes(b'HIASTM01', 'little')
WORKSPACE = 90688
SOURCE = r'''
def statement_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 90688 + ((length(s) + 7) >> 3) or length(s) > 8388608:
        return 4294967293
    limit = get(w, 25040)
    entry = get(w, 25048)
    mode = get(w, 8616)
    if limit > 128 or entry > 1 or mode > 1:
        return 4294967293
    i = 90688
    while i < length(w):
        store(w, i, 0)
        i = i + 1
    statement_reset(w, 0, 0)
    expr_first(s, o, w)
    root = statement_parse(s, o, w, entry)
    if mode == 0 and (get(w, 48) != 0 or get(w, 216) != 0):
        return 4294967295
    count = get(w, 200)
    base = 64 + count * 128
    used = base + get(w, 208)
    if used > length(o):
        return 4294967294
    statement_reset(w, 1, base)
    expr_first(s, o, w)
    root = statement_parse(s, o, w, entry)
    put(o, 0, @MAGIC@ ^ mode)
    put(o, 8, count)
    put(o, 16, base)
    put(o, 24, used)
    put(o, 32, get(w, 184))
    put(o, 40, get(w, 192))
    put(o, 48, 1 + mode)
    put(o, 56, choose(mode == 0, root, get(w, 216)))
    return used

def statement_reset(w:mutbuf, phase:u64, base:u64) -> u64:
    expr_reset(w, phase, base)
    put(w, 25024, 0)
    put(w, 25032, 0)
    put(w, 25056, 0)
    return 0

def statement_frame(w:mutbuf) -> u64:
    return 25152 + (get(w, 25024) - 1) * 128

def statement_push(w:mutbuf, entry:u64) -> u64:
    level = get(w, 25024)
    if level >= 512:
        return type_error(w, 1)
    at = 25152 + level * 128
    field = 0
    while field < 128:
        put(w, at + field, 0)
        field = field + 8
    put(w, at + 16, entry)
    put(w, at + 24, get(w, 152))
    put(w, at + 32, get(w, 168))
    put(w, at + 40, get(w, 176))
    put(w, 25024, level + 1)
    return 0

def statement_span(o:mutbuf, w:mutbuf, node:u64, at:u64) -> u64:
    type_set(o, w, node, 80, get(w, at + 24))
    type_set(o, w, node, 88, get(w, 184))
    type_set(o, w, node, 96, get(w, at + 32))
    type_set(o, w, node, 104, get(w, at + 40))
    return 0

def statement_done(o:mutbuf, w:mutbuf) -> u64:
    at = statement_frame(w)
    node = get(w, at + 8)
    statement_span(o, w, node, at)
    if get(w, at + 16) == 0:
        put(w, 25056, get(w, 25056) - 1)
    put(w, 25032, node)
    put(w, 25024, get(w, 25024) - 1)
    return 0

def statement_expression(s:readbuf, o:mutbuf, w:mutbuf, node:u64, allow:u64) -> u64:
    put(w, 8520, get(w, 25040) - get(w, 25056))
    root = expr_parse(s, o, w, 0, allow)
    if get(w, 216) == 0 and get(w, 48) == 0:
        expr_attach(o, w, node, root)
    return root

def statement_name(s:readbuf, o:mutbuf, w:mutbuf, node:u64, code:u64) -> u64:
    if get(w, 128) != 1:
        return type_error(w, code)
    begin = get(w, 136)
    end = get(w, 144)
    offset = type_text(s, o, w, begin, end)
    type_set(o, w, node, 40, offset)
    type_set(o, w, node, 48, end - begin)
    return type_consume(s, o, w)

def statement_pattern(s:readbuf, o:mutbuf, w:mutbuf, node:u64) -> u64:
    if get(w, 128) != 1:
        return type_error(w, 6)
    begin = get(w, 136)
    end = get(w, 144)
    offset = type_text(s, o, w, begin, end)
    size = end - begin
    parts = 1
    type_consume(s, o, w)
    while get(w, 128) == 522 and get(w, 216) == 0 and get(w, 48) == 0:
        type_consume(s, o, w)
        if get(w, 128) != 1:
            type_error(w, 7)
        else:
            type_colons(o, w)
            begin = get(w, 136)
            end = get(w, 144)
            type_text(s, o, w, begin, end)
            size = size + 2 + end - begin
            parts = parts + 1
            type_consume(s, o, w)
    type_set(o, w, node, 40, offset)
    type_set(o, w, node, 48, size)
    if parts < 2 and get(w, 216) == 0 and get(w, 48) == 0:
        at = statement_frame(w)
        expr_error_at(w, 213, get(w, at + 24), get(w, at + 56), get(w, at + 32), get(w, at + 40))
    return 0

def statement_parse(s:readbuf, o:mutbuf, w:mutbuf, entry:u64) -> u64:
    statement_push(w, entry)
    while get(w, 25024) != 0 and get(w, 216) == 0 and get(w, 48) == 0:
        at = statement_frame(w)
        state = get(w, at)
        kind = get(w, 128)
        node = get(w, at + 8)
        if state == 0:
            mode = get(w, at + 16)
            if mode == 0:
                if get(w, 25056) >= get(w, 25040):
                    type_error(w, 1)
                else:
                    put(w, 25056, get(w, 25056) + 1)
                    node = type_node(o, w, 32, 18446744073709551615)
                    put(w, at + 8, node)
                    type_expect(s, o, w, 379, 201)
                    put(w, at, 1)
            elif mode == 2:
                node = type_node(o, w, 42, 18446744073709551615)
                put(w, at + 8, node)
                pattern = type_node(o, w, 43, node)
                type_link(o, w, node, pattern)
                expr_mark(o, w, pattern)
                put(w, at + 48, pattern)
                put(w, at + 56, get(w, 160))
                statement_pattern(s, o, w, pattern)
                if get(w, 128) == 296 and get(w, 216) == 0:
                    type_consume(s, o, w)
                    put(w, at, 13)
                else:
                    put(w, at, 14)
            else:
                if kind == @LET@:
                    node = type_node(o, w, 33, 18446744073709551615)
                    put(w, at + 8, node)
                    type_consume(s, o, w)
                    if get(w, 128) == @MUT@:
                        type_set(o, w, node, 72, 1)
                        type_consume(s, o, w)
                    statement_name(s, o, w, node, 203)
                    if get(w, 128) == 314 and get(w, 216) == 0:
                        type_consume(s, o, w)
                        put(w, 224, get(w, 25040) - get(w, 25056))
                        type_parse(s, o, w, node, 1)
                    type_expect(s, o, w, 317, 204)
                    statement_expression(s, o, w, node, 1)
                    type_expect(s, o, w, 315, 205)
                    statement_done(o, w)
                elif kind == @RETURN@:
                    node = type_node(o, w, 34, 18446744073709551615)
                    put(w, at + 8, node)
                    type_consume(s, o, w)
                    if get(w, 128) != 315:
                        statement_expression(s, o, w, node, 1)
                    type_expect(s, o, w, 315, 206)
                    statement_done(o, w)
                elif kind == @FOR@:
                    node = type_node(o, w, 35, 18446744073709551615)
                    put(w, at + 8, node)
                    type_consume(s, o, w)
                    statement_name(s, o, w, node, 207)
                    type_expect(s, o, w, @IN@, 208)
                    statement_expression(s, o, w, node, 0)
                    type_expect(s, o, w, 513, 209)
                    statement_expression(s, o, w, node, 0)
                    put(w, at, 3)
                    statement_push(w, 0)
                elif kind == @WHILE@ or kind == @IF@ or kind == @UNSAFE@:
                    node = type_node(o, w, choose(kind == @WHILE@, 36, choose(kind == @IF@, 37, 38)), 18446744073709551615)
                    put(w, at + 8, node)
                    put(w, at + 64, kind)
                    type_consume(s, o, w)
                    if kind != @UNSAFE@:
                        statement_expression(s, o, w, node, 0)
                    put(w, at, 4)
                    statement_push(w, 0)
                elif kind == @MATCH@:
                    node = type_node(o, w, 39, 18446744073709551615)
                    put(w, at + 8, node)
                    type_consume(s, o, w)
                    statement_expression(s, o, w, node, 0)
                    type_expect(s, o, w, 379, 201)
                    put(w, at, 11)
                else:
                    node = type_node(o, w, 41, 18446744073709551615)
                    put(w, at + 8, node)
                    target = statement_expression(s, o, w, node, 1)
                    if get(w, 128) == 317 and get(w, 216) == 0 and get(w, 48) == 0:
                        type_consume(s, o, w)
                        target_kind = get(w, 8536)
                        if target_kind != 20 and target_kind != 23 and target_kind != 22:
                            if get(w, 232) == 1:
                                target_at = 64 + target * 128
                                expr_error_at(w, 211, get(o, target_at + 80), get(o, target_at + 88), get(o, target_at + 96), get(o, target_at + 104))
                            else:
                                expr_error_at(w, 211, get(w, 25064), get(w, 25072), get(w, 25080), get(w, 25088))
                        else:
                            type_set(o, w, node, 0, 40)
                            statement_expression(s, o, w, node, 1)
                            type_expect(s, o, w, 315, 212)
                    else:
                        type_expect(s, o, w, 315, 210)
                    statement_done(o, w)
        elif state == 1:
            if kind == 381:
                type_consume(s, o, w)
                statement_done(o, w)
            elif kind == 0:
                type_error(w, 202)
            else:
                put(w, at, 2)
                statement_push(w, 1)
        elif state == 2:
            expr_attach(o, w, node, get(w, 25032))
            put(w, at, 1)
        elif state == 3 or state == 5 or state == 15:
            expr_attach(o, w, node, get(w, 25032))
            statement_done(o, w)
        elif state == 4:
            expr_attach(o, w, node, get(w, 25032))
            if get(w, at + 64) == @IF@ and kind == @ELSE@:
                type_consume(s, o, w)
                put(w, at, 5)
                statement_push(w, 0)
            else:
                statement_done(o, w)
        elif state == 11:
            if kind == 381:
                type_consume(s, o, w)
                statement_done(o, w)
            else:
                put(w, at, 12)
                statement_push(w, 2)
        elif state == 12:
            expr_attach(o, w, node, get(w, 25032))
            if kind == 300:
                type_consume(s, o, w)
                put(w, at, 11)
            else:
                type_expect(s, o, w, 381, 216)
                statement_done(o, w)
        elif state == 13:
            binding = type_node(o, w, 44, get(w, at + 48))
            expr_mark(o, w, binding)
            statement_name(s, o, w, binding, 214)
            type_link(o, w, get(w, at + 48), binding)
            if get(w, 128) == 300 and get(w, 216) == 0:
                type_consume(s, o, w)
            else:
                type_expect(s, o, w, 297, 104)
                put(w, at, 14)
        elif state == 14:
            statement_span(o, w, get(w, at + 48), at)
            type_expect(s, o, w, 523, 215)
            put(w, at, 15)
            statement_push(w, 0)
        else:
            type_error(w, 217)
    return get(w, 25032)
'''


def source_program():
    source = SOURCE.replace('@MAGIC@', str(MAGIC))
    for word in ('let','mut','return','for','in','while','if','unsafe','match','else'):
        source = source.replace('@'+word.upper()+'@', str(token_kind(word)))
    original = expression_program()
    for node in ast.parse(original).body:
        if node.name == 'expression_main': continue
        text = ast.get_source_segment(original, node)
        if node.name == 'type_close': text = text.replace('bit_at = 25024', 'bit_at = 90688')
        if node.name == 'expr_finish':
            # Sideband spans retain the exact assignment-target error even in
            # pass zero, where no output arena is written.
            text = text.replace('    put(w, 8512,',
                '    put(w, 25064, get(w, at + 40))\n'
                '    put(w, 25072, get(w, 184))\n'
                '    put(w, 25080, get(w, at + 48))\n'
                '    put(w, 25088, get(w, at + 56))\n'
                '    put(w, 8512,',1)
        source += '\n'+text+'\n'
    return source


def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    assert len(names)==len(nodes)
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes); functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'source_statements','functions':functions})


def main():
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/source_statements.hiaasm'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)


if __name__=='__main__':main()
