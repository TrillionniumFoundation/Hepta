"""Author complete program/module/import/declaration syntax in executable HIA.

Composes the actual source statement/expression/type/scanner definitions.
This work-in-progress authoring source is not a qualification receipt. Semantic
namespace/tree-depth/type/effect/ownership checks and host orchestration remain
explicitly foreign until their own implementations are completed.
"""
from __future__ import annotations
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.generate_hia_source_statements import source_program as statement_program
from tools.generate_hia_source_expressions import token_kind

MAGIC=int.from_bytes(b'HIADEC01','little')
WORKSPACE=92416
SOURCE=r'''
def declaration_main(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 92416 + ((length(s) + 7) >> 3) or length(s) > 8388608:
        return 4294967293
    mode = get(w, 8616)
    limit = get(w, 25040)
    if mode > 1 or limit < 1 or limit > 128:
        return 4294967293
    i = 92416
    while i < length(w):
        store(w, i, 0)
        i = i + 1
    declaration_reset(w, 0, 0)
    expr_first(s, o, w)
    root = declaration_program(s, o, w)
    if mode == 0 and (get(w, 48) != 0 or get(w, 216) != 0):
        return 4294967295
    count = get(w, 200)
    base = 64 + count * 128
    used = base + get(w, 208)
    if used > length(o):
        return 4294967294
    declaration_reset(w, 1, base)
    expr_first(s, o, w)
    root = declaration_program(s, o, w)
    put(o, 0, @MAGIC@ ^ mode)
    put(o, 8, count)
    put(o, 16, base)
    put(o, 24, used)
    put(o, 32, get(w, 184))
    put(o, 40, get(w, 192))
    put(o, 48, 1 + mode)
    put(o, 56, choose(mode == 0, root, get(w, 216)))
    return used

def declaration_reset(w:mutbuf, phase:u64, base:u64) -> u64:
    statement_reset(w, phase, base)
    i = 90688
    while i < 92416:
        put(w, i, 0)
        i = i + 8
    return 0

def declaration_save(w:mutbuf, at:u64) -> u64:
    i = 0
    while i < 256:
        put(w, at + i, get(w, i))
        i = i + 8
    return 0

def declaration_restore(w:mutbuf, at:u64) -> u64:
    i = 0
    while i < 256:
        put(w, i, get(w, at + i))
        i = i + 8
    return 0

def declaration_scan_at(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u64:
    initialize(w, 0)
    put(w, 0, at)
    return type_next(s, o, w)

def declaration_equal(s:readbuf, a:u64, z:u64, b:u64, e:u64) -> u64:
    if z - a != e - b:
        return 0
    while a < z:
        if byte(s, a) != byte(s, b):
            return 0
        a = a + 1
        b = b + 1
    return 1

def declaration_duplicate(s:readbuf, o:mutbuf, w:mutbuf, group:u64, begin:u64, end:u64) -> u64:
    declaration_save(w, 91008)
    declaration_scan_at(s, o, w, group)
    duplicate = 0
    while get(w, 136) < begin and get(w, 128) != 0 and get(w, 48) == 0:
        kind = get(w, 128)
        if kind == 1 or kind == @UNSAFE@:
            if declaration_equal(s, begin, end, get(w, 136), get(w, 144)) != 0:
                duplicate = 1
        type_next(s, o, w)
    declaration_restore(w, 91008)
    return duplicate

def declaration_later_generic(s:readbuf, o:mutbuf, w:mutbuf, begin:u64, end:u64, stop:u64) -> u64:
    declaration_save(w, 91328)
    expect_name = 0
    found = 0
    while get(w, 136) < stop and get(w, 128) != 0 and get(w, 128) != 318 and get(w, 128) != 517 and get(w, 128) != 521 and get(w, 48) == 0:
        kind = get(w, 128)
        if kind == 300:
            expect_name = 1
        elif expect_name != 0:
            if kind == 1 and declaration_equal(s, begin, end, get(w, 136), get(w, 144)) != 0:
                found = 1
            expect_name = 0
        type_next(s, o, w)
    declaration_restore(w, 91328)
    return found

def declaration_struct_bad_bound(s:readbuf, o:mutbuf, w:mutbuf, begin:u64, end:u64) -> u64:
    declaration_save(w, 91008)
    declaration_scan_at(s, o, w, begin)
    invalid = 0
    running = 1
    while running != 0 and get(w, 136) < end and get(w, 128) != 0 and get(w, 128) != 318 and get(w, 128) != 517 and get(w, 128) != 521 and get(w, 48) == 0:
        kind = get(w, 128)
        name_begin = get(w, 136)
        name_end = get(w, 144)
        type_next(s, o, w)
        if kind == 1 and get(w, 128) == 314:
            type_next(s, o, w)
            noncopy = matches(s, get(w, 136), get(w, 144), @COPY@, 0, 4) == 0
            type_next(s, o, w)
            if noncopy and declaration_later_generic(s, o, w, name_begin, name_end, end) == 0:
                invalid = 1
        if get(w, 128) == 300 and get(w, 216) == 0 and get(w, 48) == 0:
            type_next(s, o, w)
        else:
            running = 0
    declaration_restore(w, 91008)
    return invalid

def declaration_start(w:mutbuf) -> u64:
    put(w, 90704, get(w, 152))
    put(w, 90712, get(w, 168))
    put(w, 90720, get(w, 176))
    return 0

def declaration_end(o:mutbuf, w:mutbuf, node:u64) -> u64:
    type_set(o, w, node, 88, get(w, 184))
    return 0

def declaration_extent(o:mutbuf, w:mutbuf, node:u64) -> u64:
    type_set(o, w, node, 80, get(w, 90704))
    type_set(o, w, node, 88, get(w, 184))
    type_set(o, w, node, 96, get(w, 90712))
    type_set(o, w, node, 104, get(w, 90720))
    return 0

def declaration_name(s:readbuf, o:mutbuf, w:mutbuf, node:u64, code:u64) -> u64:
    if get(w, 216) != 0 or get(w, 48) != 0:
        return 0
    if get(w, 128) != 1:
        return type_error(w, code)
    expr_text(s, o, w, node)
    return type_consume(s, o, w)

def declaration_path(s:readbuf, o:mutbuf, w:mutbuf, node:u64) -> u64:
    if get(w, 216) != 0 or get(w, 48) != 0:
        return 0
    if get(w, 128) != 1:
        return type_error(w, 6)
    expr_mark(o, w, node)
    begin = get(w, 136)
    end = get(w, 144)
    offset = type_text(s, o, w, begin, end)
    size = end - begin
    type_consume(s, o, w)
    while get(w, 128) == 522 and get(w, 48) == 0 and get(w, 216) == 0:
        type_consume(s, o, w)
        if get(w, 128) != 1:
            type_error(w, 7)
        else:
            type_colons(o, w)
            begin = get(w, 136)
            end = get(w, 144)
            type_text(s, o, w, begin, end)
            size = size + 2 + end - begin
            type_consume(s, o, w)
    type_set(o, w, node, 40, offset)
    type_set(o, w, node, 48, size)
    return declaration_end(o, w, node)

def declaration_type(s:readbuf, o:mutbuf, w:mutbuf, parent:u64) -> u64:
    put(w, 224, get(w, 25040))
    return type_parse(s, o, w, parent, 1)

def declaration_abi(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, 216) != 0 or get(w, 48) != 0:
        return 0
    if get(w, 128) != 5:
        return type_error(w, 304)
    valid = matches(s, get(w, 136), get(w, 144), 67, 0, 1)
    start = get(w, 152)
    end = get(w, 160)
    line = get(w, 168)
    column = get(w, 176)
    type_consume(s, o, w)
    if valid == 0:
        expr_error_at(w, 305, start, end, line, column)
    return 0

def declaration_generics(s:readbuf, o:mutbuf, w:mutbuf, parent:u64, function_style:u64) -> u64:
    if get(w, 216) != 0 or get(w, 48) != 0:
        return 0
    put(w, 91616, 0)
    if get(w, 128) != 316:
        return 0
    type_consume(s, o, w)
    put(w, 91616, get(w, 136))
    running = 1
    while running != 0 and get(w, 48) == 0 and get(w, 216) == 0:
        if function_style != 0 and get(w, 128) == 2:
            node = type_node(o, w, 63, parent)
            expr_text(s, o, w, node)
            type_link(o, w, parent, node)
            type_consume(s, o, w)
        else:
            node = type_node(o, w, 55, parent)
            type_link(o, w, parent, node)
            declaration_name(s, o, w, node, choose(function_style != 0, 306, 307))
            if function_style != 0 and get(w, 128) == 314 and get(w, 216) == 0:
                type_consume(s, o, w)
                bound = type_node(o, w, 56, node)
                type_link(o, w, node, bound)
                declaration_name(s, o, w, bound, 308)
            declaration_end(o, w, node)
        if get(w, 128) == 300 and get(w, 216) == 0:
            type_consume(s, o, w)
        else:
            running = 0
    return type_close(s, o, w)

def declaration_struct(s:readbuf, o:mutbuf, w:mutbuf, parent:u64) -> u64:
    node = type_node(o, w, 52, parent)
    put(w, 90696, node)
    type_link(o, w, parent, node)
    flags = 0
    if get(w, 128) == @PUB@:
        flags = 1
        type_consume(s, o, w)
    if get(w, 128) == @REPR@ and get(w, 216) == 0:
        flags = flags | 2
        type_consume(s, o, w)
        type_expect(s, o, w, 296, 302)
        if get(w, 128) != 1:
            type_error(w, 310)
        else:
            valid = matches(s, get(w, 136), get(w, 144), 67, 0, 1)
            start = get(w, 152)
            end = get(w, 160)
            line = get(w, 168)
            column = get(w, 176)
            type_consume(s, o, w)
            if valid == 0:
                expr_error_at(w, 311, start, end, line, column)
        type_expect(s, o, w, 297, 104)
    type_set(o, w, node, 72, flags)
    type_expect(s, o, w, @STRUCT@, 312)
    declaration_name(s, o, w, node, 313)
    declaration_generics(s, o, w, node, 1)
    if get(w, 91616) != 0 and get(w, 216) == 0 and get(w, 48) == 0:
        if declaration_struct_bad_bound(s, o, w, get(w, 91616), get(w, 192)) != 0:
            type_error(w, 314)
    type_expect(s, o, w, 379, 201)
    running = 1
    while running != 0 and get(w, 128) != 381 and get(w, 216) == 0 and get(w, 48) == 0:
        expr_field(w)
        if get(w, 216) != 0 or get(w, 48) != 0:
            return 0
        field = type_node(o, w, 57, node)
        type_link(o, w, node, field)
        expr_text(s, o, w, field)
        type_consume(s, o, w)
        type_expect(s, o, w, 314, 103)
        declaration_type(s, o, w, field)
        declaration_end(o, w, field)
        if get(w, 128) == 300 and get(w, 216) == 0 and get(w, 48) == 0:
            type_consume(s, o, w)
        else:
            running = 0
    type_expect(s, o, w, 381, 315)
    return declaration_extent(o, w, node)

def declaration_enum(s:readbuf, o:mutbuf, w:mutbuf, parent:u64) -> u64:
    node = type_node(o, w, 53, parent)
    put(w, 90696, node)
    type_link(o, w, parent, node)
    if get(w, 128) == @PUB@:
        type_set(o, w, node, 72, 1)
        type_consume(s, o, w)
    type_expect(s, o, w, @ENUM@, 316)
    declaration_name(s, o, w, node, 317)
    declaration_generics(s, o, w, node, 0)
    type_expect(s, o, w, 379, 201)
    running = 1
    while running != 0 and get(w, 128) != 381 and get(w, 216) == 0 and get(w, 48) == 0:
        variant = type_node(o, w, 62, node)
        type_link(o, w, node, variant)
        declaration_name(s, o, w, variant, 318)
        if get(w, 128) == 296 and get(w, 216) == 0:
            type_consume(s, o, w)
            declaration_type(s, o, w, variant)
            while get(w, 128) == 300 and get(w, 216) == 0 and get(w, 48) == 0:
                type_consume(s, o, w)
                declaration_type(s, o, w, variant)
            type_expect(s, o, w, 297, 104)
        declaration_end(o, w, variant)
        if get(w, 128) == 300 and get(w, 216) == 0 and get(w, 48) == 0:
            type_consume(s, o, w)
        else:
            running = 0
    type_expect(s, o, w, 381, 319)
    return declaration_extent(o, w, node)

def declaration_mode(s:readbuf, o:mutbuf, w:mutbuf, node:u64, allow_take:u64) -> u64:
    if get(w, 216) != 0 or get(w, 48) != 0:
        return 0
    kind = get(w, 128)
    mode = 0
    if kind == @READ@ or kind == @MUT@ or (allow_take != 0 and kind == @TAKE@):
        mode = choose(kind == @READ@, 1, choose(kind == @MUT@, 2, 3))
        type_consume(s, o, w)
    type_set(o, w, node, 72, mode)
    if get(w, 128) == 2:
        lifetime = type_node(o, w, 8, node)
        type_link(o, w, node, lifetime)
        begin = get(w, 136)
        end = get(w, 144)
        offset = type_text(s, o, w, begin, end)
        type_set(o, w, lifetime, 40, offset)
        type_set(o, w, lifetime, 48, end - begin)
        type_consume(s, o, w)
    return declaration_type(s, o, w, node)

def declaration_effects(s:readbuf, o:mutbuf, w:mutbuf, parent:u64) -> u64:
    if get(w, 216) != 0 or get(w, 48) != 0:
        return 0
    type_expect(s, o, w, @EFFECTS@, 320)
    type_expect(s, o, w, 379, 201)
    put(w, 90760, get(w, 136))
    running = 1
    while running != 0 and get(w, 128) != 381 and get(w, 216) == 0 and get(w, 48) == 0:
        if get(w, 128) != 1 and get(w, 128) != @UNSAFE@:
            type_error(w, 321)
        else:
            begin = get(w, 136)
            end = get(w, 144)
            duplicate = declaration_duplicate(s, o, w, get(w, 90760), begin, end)
            effect = type_node(o, w, 58, parent)
            type_link(o, w, parent, effect)
            expr_text(s, o, w, effect)
            start = get(w, 152)
            finish = get(w, 160)
            line = get(w, 168)
            column = get(w, 176)
            type_consume(s, o, w)
            if duplicate != 0:
                put(w, 90792, begin)
                put(w, 90800, end)
                expr_error_at(w, 330, start, finish, line, column)
            if get(w, 128) == 300 and get(w, 216) == 0:
                type_consume(s, o, w)
            else:
                running = 0
    return type_expect(s, o, w, 381, 322)

def declaration_resources(s:readbuf, o:mutbuf, w:mutbuf, parent:u64) -> u64:
    if get(w, 216) != 0 or get(w, 48) != 0:
        return 0
    type_consume(s, o, w)
    type_expect(s, o, w, 379, 201)
    put(w, 90760, get(w, 136))
    while get(w, 128) != 381 and get(w, 216) == 0 and get(w, 48) == 0:
        if get(w, 128) != 1:
            type_error(w, 332)
        else:
            begin = get(w, 136)
            end = get(w, 144)
            duplicate = declaration_duplicate(s, o, w, get(w, 90760), begin, end)
            resource = type_node(o, w, 59, parent)
            type_link(o, w, parent, resource)
            expr_text(s, o, w, resource)
            start = get(w, 152)
            finish = get(w, 160)
            line = get(w, 168)
            column = get(w, 176)
            type_consume(s, o, w)
            if duplicate != 0:
                put(w, 90792, begin)
                put(w, 90800, end)
                expr_error_at(w, 331, start, finish, line, column)
            type_expect(s, o, w, 317, 204)
            kind = get(w, 128)
            if kind != 3 and kind != 4 and kind != @TRUE@ and kind != @FALSE@:
                type_error(w, 333)
            elif get(w, 216) == 0:
                value = type_node(o, w, choose(kind == 3, 16, choose(kind == 4, 17, 18)), resource)
                type_link(o, w, resource, value)
                expr_mark(o, w, value)
                type_set(o, w, value, 56, get(w, 136))
                type_set(o, w, value, 64, get(w, 144) - get(w, 136))
                type_set(o, w, value, 72, kind)
                type_consume(s, o, w)
            type_expect(s, o, w, 315, 334)
            declaration_end(o, w, resource)
    return type_expect(s, o, w, 381, 335)

def declaration_function(s:readbuf, o:mutbuf, w:mutbuf, parent:u64) -> u64:
    node = type_node(o, w, 54, parent)
    put(w, 90696, node)
    type_link(o, w, parent, node)
    flags = 0
    if get(w, 128) == @EXTERN@:
        flags = 2
        type_consume(s, o, w)
        declaration_abi(s, o, w)
    else:
        if get(w, 128) == @PUB@:
            flags = 1
            type_consume(s, o, w)
        if get(w, 128) == @EXPORT@ and get(w, 216) == 0:
            flags = flags | 4
            type_consume(s, o, w)
            declaration_abi(s, o, w)
    type_set(o, w, node, 72, flags)
    type_expect(s, o, w, @FN@, 323)
    declaration_name(s, o, w, node, 324)
    declaration_generics(s, o, w, node, 1)
    type_expect(s, o, w, 296, 302)
    running = 1
    while running != 0 and get(w, 128) != 297 and get(w, 216) == 0 and get(w, 48) == 0:
        param = type_node(o, w, 57, node)
        type_link(o, w, node, param)
        declaration_name(s, o, w, param, 325)
        type_expect(s, o, w, 314, 103)
        declaration_mode(s, o, w, param, 1)
        declaration_end(o, w, param)
        if get(w, 128) == 300 and get(w, 216) == 0 and get(w, 48) == 0:
            type_consume(s, o, w)
        else:
            running = 0
    type_expect(s, o, w, 297, 326)
    type_expect(s, o, w, 512, 327)
    returns = type_node(o, w, 60, node)
    type_link(o, w, node, returns)
    expr_mark(o, w, returns)
    declaration_mode(s, o, w, returns, 0)
    declaration_end(o, w, returns)
    if get(w, 128) == 1 and get(w, 216) == 0:
        if matches(s, get(w, 136), get(w, 144), @FROM@, 0, 4) != 0:
            type_consume(s, o, w)
            origin = type_node(o, w, 61, node)
            type_link(o, w, node, origin)
            declaration_name(s, o, w, origin, 328)
    declaration_effects(s, o, w, node)
    if (flags & 2) != 0:
        body = type_node(o, w, 64, node)
        type_link(o, w, node, body)
        expr_mark(o, w, body)
        type_set(o, w, body, 88, get(w, 152))
        type_expect(s, o, w, 315, 329)
    else:
        if get(w, 128) == @RESOURCES@ and get(w, 216) == 0:
            declaration_resources(s, o, w, node)
        body = statement_parse(s, o, w, 0)
        if get(w, 216) == 0 and get(w, 48) == 0:
            expr_attach(o, w, node, body)
    return declaration_extent(o, w, node)

def declaration_program(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    root = type_node(o, w, 48, 18446744073709551615)
    type_set(o, w, root, 96, 1)
    type_set(o, w, root, 104, 1)
    if get(w, 128) == @MODULE@:
        type_consume(s, o, w)
        node = type_node(o, w, 49, root)
        type_link(o, w, root, node)
        declaration_path(s, o, w, node)
        type_expect(s, o, w, 315, 336)
    while get(w, 128) == @IMPORT@ and get(w, 216) == 0 and get(w, 48) == 0:
        declaration_start(w)
        type_consume(s, o, w)
        node = type_node(o, w, 50, root)
        type_link(o, w, root, node)
        declaration_path(s, o, w, node)
        if get(w, 128) == @AS@ and get(w, 216) == 0:
            type_consume(s, o, w)
            alias = type_node(o, w, 51, node)
            type_link(o, w, node, alias)
            declaration_name(s, o, w, alias, 337)
        type_expect(s, o, w, 315, 336)
        declaration_extent(o, w, node)
    while get(w, 128) != 0 and get(w, 216) == 0 and get(w, 48) == 0:
        declaration_start(w)
        kind = get(w, 128)
        following = 0
        if kind == @PUB@:
            declaration_save(w, 91008)
            type_next(s, o, w)
            following = get(w, 128)
            declaration_restore(w, 91008)
        if kind == @STRUCT@ or kind == @REPR@ or (kind == @PUB@ and (following == @STRUCT@ or following == @REPR@)):
            declaration_struct(s, o, w, root)
        elif kind == @ENUM@ or (kind == @PUB@ and following == @ENUM@):
            declaration_enum(s, o, w, root)
        elif kind == @PUB@ or kind == @EXPORT@ or kind == @FN@ or kind == @EXTERN@:
            declaration_function(s, o, w, root)
        else:
            type_error(w, 301)
    if get(w, 216) == 0 and get(w, 48) == 0:
        put(w, 184, get(w, 152))
        put(w, 192, get(w, 136))
        type_set(o, w, root, 88, get(w, 184))
    return root
'''


def source_program():
    source=SOURCE.replace('@MAGIC@',str(MAGIC))
    for word in ('unsafe','pub','repr','struct','enum','read','mut','take','effects',
                 'true','false','extern','export','fn','resources','module','import','as'):
        source=source.replace('@'+word.upper()+'@',str(token_kind(word)))
    source=source.replace('@COPY@',str(int.from_bytes(b'Copy','little'))).replace('@FROM@',str(int.from_bytes(b'from','little')))
    original=statement_program()
    for node in ast.parse(original).body:
        if node.name=='statement_main':continue
        text=ast.get_source_segment(original,node)
        if node.name=='type_close':text=text.replace('bit_at = 90688','bit_at = 92416')
        source+='\n'+text+'\n'
    return source


def document():
    nodes=ast.parse(source_program()).body
    names={node.name:'f'+str(i) for i,node in enumerate(nodes)}
    assert len(names)==len(nodes)
    signatures={node.name:([a.annotation.id for a in node.args.args],node.returns.id) for node in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        builder=Builder(node,names,signatures,total);builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(v) for v in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':'source_declarations','functions':functions})


def main():
    path=Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/source_declarations.hiaasm'
    path.write_text(render_assembly(document()));print(path.name,path.stat().st_size)


if __name__=='__main__':main()
