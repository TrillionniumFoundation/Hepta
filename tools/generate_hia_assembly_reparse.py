"""Author a bounded byte-only inverse of the canonical assembly formatter.

This internal representation component does not admit general assembly syntax
or Core execution.  It accepts the formatter's exact LF/spacing/name grammar,
preserves v6/v7/v8, empty exports and returned-loan metadata, and emits Core JSON.
The existing core_json_bytes image supplies canonical serialization separately.
No Python parser, JSON graph or callback is used by the emitted HIA program.
"""
from __future__ import annotations

import ast
import copy
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_preflight import SOURCE as PREFLIGHT_SOURCE
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

SOURCE_NAME = 'examples/hia_bootstrap/assembly_reparse.hepta'
CAPACITY = 1 << 20
FUNCTION_BASE = 256
BLOCK_BASE = FUNCTION_BASE + 256 * 16
JSON_BASE = BLOCK_BASE + 4096 * 16
JSON_BYTES = 128 + 17 * 32
KEY_BASE = JSON_BASE + JSON_BYTES
KEY_BYTES = 4096 * 8
WORKSPACE_BYTES = KEY_BASE + KEY_BYTES
BAD_SYNTAX = 0xffffffff
BAD_LIMIT = 0xfffffffe
BAD_ABI = 0xfffffffd
BAD_DUPLICATE = 0xfffffffc
BAD_OUTPUT = 0xfffffffb

POLICY = r'''
def reparse(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > CAPACITY or length(o) > CAPACITY or length(w) > CAPACITY:
        return BAD_ABI
    if length(w) < WORKSPACE_BYTES:
        return BAD_ABI
    i = 0
    while i < 128:
        put(w, i, 0)
        i = i + 8
    lines = 1
    i = 0
    while i < length(s):
        ch = byte(s, i)
        if ch < 32 and ch != 10:
            return BAD_SYNTAX
        if ch == 10:
            lines = lines + 1
            if lines > 16384:
                return BAD_LIMIT
        if ch == 239 and length(s) - i >= 3:
            if byte(s, i + 1) == 187 and byte(s, i + 2) == 191:
                return BAD_SYNTAX
        i = i + 1
    if length(s) == 0:
        return BAD_SYNTAX
    line(s, w)
    expect(s, w, 'hia-asm.v1 hepta.hia.program.v')
    version = peek(s, w)
    if version < 54 or version > 56:
        return BAD_SYNTAX
    put(w, 56, version)
    put(w, 8, get(w, 8) + 1)
    expect(s, w, ' ')
    text(o, w, '{"schema":"hepta.hia.program.v')
    append(o, w, version)
    text(o, w, '","module":')
    quoted_name(s, o, w, 0)
    finish_line(s, w)
    if prefix(s, w, 'exports(') == 1:
        expect(s, w, 'exports(')
        text(o, w, ',"exports":')
        names(s, o, w, 41)
        expect(s, w, ')')
        finish_line(s, w)
    text(o, w, ',"functions":[')
    while get(w, 8) < length(s) and get(w, 0) == 0:
        if get(w, 32) != 0:
            append(o, w, 44)
        function(s, o, w)
    if get(w, 32) == 0:
        fail(w, BAD_SYNTAX)
    text(o, w, ']}')
    if get(w, 0) != 0:
        return get(w, 0)
    return get(w, 24)

def function(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, 32) >= 256:
        return fail(w, BAD_LIMIT)
    expect(s, w, 'fn ')
    text(o, w, '{"name":')
    quoted_name(s, o, w, 0)
    unique(s, w, FUNCTION_BASE, get(w, 32))
    put(w, 32, get(w, 32) + 1)
    put(w, 64, 0)
    expect(s, w, '(')
    text(o, w, ',"params":')
    parameters(s, o, w, 41)
    expect(s, w, ') -> (')
    text(o, w, ',"returns":')
    names(s, o, w, 41)
    expect(s, w, ') effects(')
    text(o, w, ',"effects":')
    names(s, o, w, 41)
    expect(s, w, ') entry(')
    text(o, w, ',"entry":')
    quoted_name(s, o, w, 0)
    expect(s, w, ')')
    if prefix(s, w, ' return_loans(') == 1:
        if get(w, 56) != 56:
            return fail(w, BAD_SYNTAX)
        expect(s, w, ' return_loans(')
        text(o, w, ',"return_loans":')
        loans(s, o, w)
        expect(s, w, ')')
    finish_line(s, w)
    text(o, w, ',"blocks":[')
    while prefix(s, w, 'block ') == 1 and get(w, 0) == 0:
        if get(w, 64) != 0:
            append(o, w, 44)
        block(s, o, w)
    if get(w, 64) == 0:
        fail(w, BAD_SYNTAX)
    expect(s, w, 'end')
    finish_line(s, w)
    text(o, w, ']}')
    return 0

def block(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, 40) >= 4096:
        return fail(w, BAD_LIMIT)
    expect(s, w, 'block ')
    text(o, w, '{"id":')
    quoted_name(s, o, w, 0)
    unique(s, w, BLOCK_BASE, get(w, 64))
    put(w, 64, get(w, 64) + 1)
    put(w, 40, get(w, 40) + 1)
    expect(s, w, '(')
    text(o, w, ',"params":')
    parameters(s, o, w, 41)
    expect(s, w, ')')
    finish_line(s, w)
    text(o, w, ',"ops":[')
    put(w, 72, 0)
    while prefix(s, w, '  ') == 1 and term_kind(s, w) == 0 and get(w, 0) == 0:
        if get(w, 72) != 0:
            append(o, w, 44)
        instruction(s, o, w)
        put(w, 72, get(w, 72) + 1)
    text(o, w, '],"term":')
    terminator(s, o, w)
    append(o, w, 125)
    return 0

def instruction(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    if get(w, 48) >= 16384:
        return fail(w, BAD_LIMIT)
    put(w, 48, get(w, 48) + 1)
    expect(s, w, '  ')
    text(o, w, '{"out":')
    if prefix(s, w, '_ = ') == 1:
        expect(s, w, '_')
        text(o, w, '[]')
    else:
        parameters(s, o, w, 32)
    expect(s, w, ' = ')
    text(o, w, ',"op":')
    quoted_name(s, o, w, 1)
    expect(s, w, '(')
    text(o, w, ',"args":')
    names(s, o, w, 41)
    expect(s, w, ')')
    text(o, w, ',"attrs":')
    if get(w, 8) == get(w, 16):
        text(o, w, '{}')
    else:
        expect(s, w, ' ')
        attributes(s, o, w)
    append(o, w, 125)
    finish_line(s, w)
    return 0

def term_kind(s:readbuf, w:mutbuf) -> u64:
    if prefix(s, w, '  ret(') == 1:
        return 1
    if prefix(s, w, '  jump ') == 1:
        return 2
    if prefix(s, w, '  branch ') == 1:
        return 3
    if prefix(s, w, '  trap ') == 1:
        return 4
    return 0

def terminator(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    kind = term_kind(s, w)
    if kind == 1:
        expect(s, w, '  ret(')
        text(o, w, '{"op":"ret","values":')
        names(s, o, w, 41)
        expect(s, w, ')')
    else:
        if kind == 2:
            expect(s, w, '  jump ')
            text(o, w, '{"op":"jump",')
            edge(s, o, w)
        else:
            if kind == 3:
                expect(s, w, '  branch ')
                text(o, w, '{"op":"branch","cond":')
                quoted_name(s, o, w, 0)
                expect(s, w, ' ')
                text(o, w, ',"then":{')
                edge(s, o, w)
                expect(s, w, ' ')
                text(o, w, '},"else":{')
                edge(s, o, w)
                append(o, w, 125)
            else:
                if kind != 4:
                    return fail(w, BAD_SYNTAX)
                expect(s, w, '  trap ')
                text(o, w, '{"op":"trap","code":')
                quoted_name(s, o, w, 0)
    append(o, w, 125)
    finish_line(s, w)
    return 0

def edge(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    text(o, w, '"target":')
    quoted_name(s, o, w, 0)
    expect(s, w, '(')
    text(o, w, ',"args":')
    names(s, o, w, 41)
    expect(s, w, ')')
    return 0

def names(s:readbuf, o:mutbuf, w:mutbuf, closing:u64) -> u64:
    append(o, w, 91)
    n = 0
    if peek(s, w) != closing:
        going = True
        while going and get(w, 0) == 0:
            if n >= 256:
                return fail(w, BAD_LIMIT)
            if n != 0:
                expect(s, w, ',')
                append(o, w, 44)
            quoted_name(s, o, w, 0)
            n = n + 1
            going = peek(s, w) != closing
    append(o, w, 93)
    return 0

def parameters(s:readbuf, o:mutbuf, w:mutbuf, closing:u64) -> u64:
    append(o, w, 91)
    n = 0
    if peek(s, w) != closing:
        going = True
        while going and get(w, 0) == 0:
            if n >= 256:
                return fail(w, BAD_LIMIT)
            if n != 0:
                expect(s, w, ',')
                append(o, w, 44)
            text(o, w, '{"name":')
            quoted_name(s, o, w, 0)
            expect(s, w, ':')
            text(o, w, ',"type":')
            quoted_name(s, o, w, 0)
            append(o, w, 125)
            n = n + 1
            going = peek(s, w) != closing
    append(o, w, 93)
    return 0

def loans(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    expect(s, w, '[')
    append(o, w, 91)
    n = 0
    if peek(s, w) != 93:
        going = True
        while going and get(w, 0) == 0:
            if n >= 256:
                return fail(w, BAD_LIMIT)
            if n != 0:
                expect(s, w, ',')
                append(o, w, 44)
            if prefix(s, w, 'null') == 1:
                expect(s, w, 'null')
                text(o, w, 'null')
            else:
                expect(s, w, '"')
                quoted_name(s, o, w, 0)
                expect(s, w, '"')
            n = n + 1
            going = peek(s, w) != 93
    expect(s, w, ']')
    append(o, w, 93)
    return 0

def attributes(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    start = get(w, 8)
    end = get(w, 16)
    if start >= end or byte(s, start) != 123 or byte(s, end - 1) != 125:
        return fail(w, BAD_SYNTAX)
    put(w, JSON_BASE + 48, 2048)
    put(w, JSON_BASE + 56, 16)
    status = widen(aj_preflight(s, w, start, end - start))
    if status != 0:
        code = BAD_SYNTAX
        if status == 2:
            code = BAD_LIMIT
        if status == 4:
            code = BAD_DUPLICATE
        if status == 3:
            code = BAD_ABI
        return fail(w, code)
    copy_span(s, o, w, start, end - start)
    put(w, 8, end)
    return 0

def quoted_name(s:readbuf, o:mutbuf, w:mutbuf, dots:u64) -> u64:
    if get(w, 0) != 0:
        return 0
    start = get(w, 8)
    end = get(w, 16)
    if start >= end:
        return fail(w, BAD_SYNTAX)
    ch = byte(s, start)
    if is_alpha(ch) == 0:
        return fail(w, BAD_SYNTAX)
    pos = start + 1
    while pos < end and is_name(byte(s, pos), dots) == 1:
        pos = pos + 1
    size = pos - start
    if size > 128:
        return fail(w, BAD_LIMIT)
    put(w, 80, start)
    put(w, 88, size)
    put(w, 8, pos)
    append(o, w, 34)
    copy_span(s, o, w, start, size)
    append(o, w, 34)
    return 0

def is_alpha(ch:u64) -> u64:
    return choose((ch >= 65 and ch <= 90) or (ch >= 97 and ch <= 122) or ch == 95, 1, 0)

def is_name(ch:u64, dots:u64) -> u64:
    return choose(is_alpha(ch) == 1 or (ch >= 48 and ch <= 57) or (dots == 1 and ch == 46), 1, 0)

def unique(s:readbuf, w:mutbuf, base:u64, count:u64) -> u64:
    if get(w, 0) != 0:
        return 0
    start = get(w, 80)
    size = get(w, 88)
    i = 0
    while i < count:
        previous = get(w, base + i * 16)
        if get(w, base + i * 16 + 8) == size:
            j = 0
            same = True
            while j < size and same:
                same = byte(s, start + j) == byte(s, previous + j)
                j = j + 1
            if same:
                return fail(w, BAD_DUPLICATE)
        i = i + 1
    put(w, base + count * 16, start)
    put(w, base + count * 16 + 8, size)
    return 0

def peek(s:readbuf, w:mutbuf) -> u64:
    if get(w, 0) != 0 or get(w, 8) >= get(w, 16):
        return 256
    return byte(s, get(w, 8))

def line(s:readbuf, w:mutbuf) -> u64:
    if get(w, 0) != 0:
        return 0
    start = get(w, 8)
    pos = start
    while pos < length(s) and byte(s, pos) != 10:
        pos = pos + 1
    if pos - start > 16384:
        return fail(w, BAD_LIMIT)
    if pos >= length(s):
        return fail(w, BAD_SYNTAX)
    put(w, 16, pos)
    return 0

def finish_line(s:readbuf, w:mutbuf) -> u64:
    if get(w, 0) != 0:
        return 0
    if get(w, 8) != get(w, 16):
        return fail(w, BAD_SYNTAX)
    put(w, 8, get(w, 16) + 1)
    put(w, 16, get(w, 8))
    if get(w, 8) < length(s):
        line(s, w)
    return 0

def fail(w:mutbuf, code:u64) -> u64:
    if get(w, 0) == 0:
        put(w, 0, code)
    return 0

def prefix(s:readbuf, w:mutbuf, n:u64, a:u64, b:u64, c:u64, d:u64) -> u64:
    if get(w, 0) != 0:
        return 0
    pos = get(w, 8)
    end = get(w, 16)
    if pos > end or n > end - pos:
        return 0
    i = 0
    while i < n:
        value = packed_byte(i, a, b, c, d)
        if byte(s, pos + i) != value:
            return 0
        i = i + 1
    return 1

def expect(s:readbuf, w:mutbuf, n:u64, a:u64, b:u64, c:u64, d:u64) -> u64:
    if prefix(s, w, n, a, b, c, d) == 0:
        return fail(w, BAD_SYNTAX)
    put(w, 8, get(w, 8) + n)
    return 0

def text(o:mutbuf, w:mutbuf, n:u64, a:u64, b:u64, c:u64, d:u64) -> u64:
    i = 0
    while i < n:
        append(o, w, packed_byte(i, a, b, c, d))
        i = i + 1
    return 0

def packed_byte(i:u64, a:u64, b:u64, c:u64, d:u64) -> u64:
    word = a
    if i >= 8:
        word = b
    if i >= 16:
        word = c
    if i >= 24:
        word = d
    return (word >> ((i & 7) * 8)) & 255

def append(o:mutbuf, w:mutbuf, value:u64) -> u64:
    if get(w, 0) != 0:
        return 0
    pos = get(w, 24)
    if pos >= length(o):
        return fail(w, BAD_OUTPUT)
    store(o, pos, value)
    put(w, 24, pos + 1)
    return 0

def copy_span(s:readbuf, o:mutbuf, w:mutbuf, start:u64, size:u64) -> u64:
    i = 0
    while i < size and get(w, 0) == 0:
        append(o, w, byte(s, start + i))
        i = i + 1
    return 0
'''


def relocated_preflight():
    """Exact original scanner, with bounded source and disjoint private regions.

    The original output key table and scanner stack become distinct offsets in
    one workspace parameter. No function receives two mutable aliases. All
    decisions and first-error branches of the original scanner are retained.
    """
    nodes = ast.parse(PREFLIGHT_SOURCE).body
    helpers = {node.name: node for node in nodes}
    selected = [node for node in nodes if node.name not in {'get', 'put', 'widen'}]
    source_names = {node.name for node in selected if any(a.arg == 's' for a in node.args.args)}
    output_names = {node.name for node in selected if any(a.arg == 'o' for a in node.args.args)}
    original_args = {node.name: [a.arg for a in node.args.args] for node in selected}

    class Relocate(ast.NodeTransformer):
        def visit_Call(self, node):
            name = node.func.id if isinstance(node.func, ast.Name) else None
            old_args = copy.deepcopy(node.args)
            node = self.generic_visit(node)
            if name in original_args:
                node.func.id = 'aj_' + name
                if name in output_names:
                    node.args.pop(original_args[name].index('o'))
                if name in source_names:
                    node.args += [ast.Name('begin', ast.Load()), ast.Name('extent', ast.Load())]
                return node
            if name == 'length' and isinstance(old_args[0], ast.Name):
                owner = old_args[0].id
                if owner == 's':
                    return ast.Name('extent', ast.Load())
                if owner == 'w':
                    return ast.Constant(JSON_BYTES)
                if owner == 'o':
                    return ast.Constant(KEY_BYTES)
            if name in {'byte', 'store', 'get', 'put'} and isinstance(old_args[0], ast.Name):
                owner = old_args[0].id
                if owner == 's':
                    node.args[1] = ast.BinOp(ast.Name('begin', ast.Load()), ast.Add(), node.args[1])
                elif owner in {'o', 'w'}:
                    node.args[0] = ast.Name('w', ast.Load())
                    node.args[1] = ast.BinOp(ast.Constant(KEY_BASE if owner == 'o' else JSON_BASE),
                                           ast.Add(), node.args[1])
            return node

    result = []
    for node in selected:
        original_name = node.name
        node = Relocate().visit(copy.deepcopy(node))
        node.name = 'aj_' + original_name
        node.args.args = [a for a in node.args.args if a.arg != 'o']
        if original_name in source_names:
            node.args.args += [ast.arg('begin', ast.Name('u64', ast.Load())),
                               ast.arg('extent', ast.Name('u64', ast.Load()))]
        result.append(node)
    result.extend(copy.deepcopy(helpers[name]) for name in ('get', 'put'))
    result.extend(ast.parse('def widen(value:u32) -> u64:\n    return value\n').body)
    return result


def source_program():
    constants = {name: value for name, value in globals().items()
                 if name.isupper() and type(value) is int}
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node
        def visit_Call(self, node):
            node = self.generic_visit(node)
            if (isinstance(node.func, ast.Name) and node.func.id in {'text', 'expect', 'prefix'}
                    and isinstance(node.args[-1], ast.Constant)
                    and type(node.args[-1].value) is str):
                raw = node.args[-1].value.encode('ascii')
                assert len(raw) <= 32
                node.args[-1:] = [ast.Constant(len(raw))] + [
                    ast.Constant(int.from_bytes(raw[i:i+8], 'little')) for i in range(0, 32, 8)]
            return node
    nodes = ast.parse(POLICY).body + relocated_preflight()
    return ast.fix_missing_locations(Expand().visit(ast.Module(body=nodes, type_ignores=[])))


def document():
    nodes = source_program().body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    signatures = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
            'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
            'entry': 'b0', 'blocks': builder.blocks})
    result = compact_authoring_cfg({'schema': 'hepta.hia.program.v8',
        'module': 'assembly_reparse', 'functions': functions})
    assert len(functions) <= 128
    assert sum(len(f['blocks']) for f in functions) <= 1536
    assert sum(len(b['ops']) for f in functions for b in f['blocks']) <= 8192
    return result


def main():
    root = Path(__file__).resolve().parents[1]
    target = root / SOURCE_NAME
    raw = render_assembly(document()).encode('utf-8')
    if len(raw) > CAPACITY:
        raise ValueError('reparser exceeds original compiler input capacity')
    target.write_bytes(raw)
    print(target.name, len(raw))


if __name__ == '__main__':
    main()
