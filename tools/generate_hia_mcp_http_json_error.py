"""Exact raw HTTP JSON syntax diagnostics for the native MCP transport.

Development author only. The emitted HIA module implements serde-compatible
Value scanning and byte-position diagnostics. A prefix operation deliberately
leaves trailing input to the transport's typed ClientJsonRpcMessage decision.
This does not claim that a syntactically valid Value is an admitted MCP message.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_system_jobctl_diagnostic_json import source_program as diagnostic_source, literal_function, ERRORS

ROOT=Path(__file__).resolve().parents[1]
SOURCE=Path('examples/hia_bootstrap/mcp_http_json_error.hepta')

ENTRY=r'''
def mcp_http_json_error(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) > 4194304 or length(o) != 8388608 or length(w) != 46137344:
        return 4294967293
    mode = get(o, 0)
    if mode > 1:
        return 4294967293
    put(w, 0, 0)
    put(w, 16384, 0)
    put(w, 16392, 0)
    put(w, 16400, 0)
    put(w, 16408, 0)
    put(w, 16416, 18446744073709551615)
    put(w, 16424, 0)
    put(w, 16432, 0)
    put(w, 16440, 0)
    put(w, 16448, 0)
    put(w, 16456, 0)
    put(w, 16464, 0)
    parse_value(s, w, 0)
    put(w, 0, get(w, 16384))
    if mode == 0 and get(w, 16408) == 0:
        point = space(s, w)
        if point != 18446744073709551615:
            failure(s, w, 19, 1)
    if get(w, 16408) == 0:
        return 0
    fix_position(w)
    return render_syntax_error(s, o, w)

def parse_value(s:readbuf, w:mutbuf, depth:u64) -> u64:
    point = space(s, w)
    if point == 18446744073709551615:
        return failure(s, w, 4, 1)
    if point == 91 or point == 123:
        if depth >= 127:
            return failure(s, w, 21, 1)
        sequence = point == 91
        closing = choose(sequence, 93, 125)
        take(s, w)
        count = 0
        while get(w, 16408) == 0:
            point = space(s, w)
            if point == 18446744073709551615:
                failure(s, w, choose(sequence, 1, 2), 1)
                return end_container(s, w, closing)
            if point == closing:
                return end_container(s, w, closing)
            if count != 0:
                if point != 44:
                    failure(s, w, choose(sequence, 6, 7), 1)
                    return end_container(s, w, closing)
                take(s, w)
                point = space(s, w)
                if point == closing:
                    failure(s, w, 18, 1)
                    return end_container(s, w, closing)
                if point == 18446744073709551615:
                    failure(s, w, 4, 1)
                    return end_container(s, w, closing)
            if sequence == False:
                if point != 34:
                    failure(s, w, 16, 1)
                    return end_container(s, w, closing)
                if string(s, w, 1) == 0:
                    return end_container(s, w, closing)
                point = space(s, w)
                if point != 58:
                    failure(s, w, choose(point == 18446744073709551615, 2, 5), 1)
                    return end_container(s, w, closing)
                take(s, w)
            if parse_value(s, w, depth + 1) == 0:
                return end_container(s, w, closing)
            count = count + 1
        return end_container(s, w, closing)
    if point == 34:
        return string(s, w, 1)
    if point == 110:
        return ident(s, w, 1819047278, 4)
    if point == 116:
        return ident(s, w, 1702195828, 4)
    if point == 102:
        return ident(s, w, 435728179558, 5)
    if point == 45 or (point >= 48 and point <= 57):
        return number(s, w, 0)
    return failure(s, w, 9, 1)

def render_syntax_error(s:readbuf, o:mutbuf, w:mutbuf) -> u64:
    code = get(w, 16408)
    if code == 0 or code > 21:
        return 4294967293
    at = literal(o, 0, code)
    line = 1
    column = 0
    index = 0
    while index < get(w, 16416):
        if byte(s, index) == 10:
            line = line + 1
            column = 0
        else:
            column = column + 1
        index = index + 1
    at = literal(o, at, 46)
    at = unsigned(o, w, at, line)
    at = literal(o, at, 47)
    return unsigned(o, w, at, column)
'''

def source_program():
    base=diagnostic_source()
    old='if at > 1048576 + 1048577:'
    assert base.count(old)==1
    base=base.replace(old,'if at > 1048576 + 4194304:')
    nodes=ast.parse(base).body
    replacement=ast.parse(ENTRY+'\n'+literal_function(dict(ERRORS)|{46:' at line ',47:' column '})).body
    names={n.name for n in replacement}
    nodes=replacement+[n for n in nodes if n.name not in names]
    retained={'mcp_http_json_error'}
    while True:
        called={x.func.id for n in nodes if n.name in retained for x in ast.walk(n) if isinstance(x,ast.Call) and isinstance(x.func,ast.Name)}
        if called <= retained:break
        retained.update(called)
    return ast.unparse(ast.Module(body=[n for n in nodes if n.name in retained],type_ignores=[]))

def program():
    return document(source_program(),'mcp_http_json_error')

if __name__=='__main__':
    target=ROOT/SOURCE
    target.write_text(render_assembly(program()))
    print(target.stat().st_size,flush=True)
