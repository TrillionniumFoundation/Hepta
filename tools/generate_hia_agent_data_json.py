"""Author Agent-data JSON hierarchy decoding, including decimal/exponent tokens.

The HIA image preserves numeric lexemes. IEEE-754 conversion and foreign object
materialization are separate, still-hosted operations; this is not a floating
point implementation or native Agent persistence.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_json_decode import source_program as integer_source
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions

MAGIC = int.from_bytes(b'HIADATA1', 'little')

ATOM = r'''
def atom(s:readbuf, index:u64) -> u64:
    size = length(s)
    if size - index >= 4:
        if byte(s, index) == 116 and byte(s, index + 1) == 114 and byte(s, index + 2) == 117 and byte(s, index + 3) == 101:
            return index + 4
        if byte(s, index) == 110 and byte(s, index + 1) == 117 and byte(s, index + 2) == 108 and byte(s, index + 3) == 108:
            return index + 4
    if size - index >= 5:
        if byte(s, index) == 102 and byte(s, index + 1) == 97 and byte(s, index + 2) == 108 and byte(s, index + 3) == 115 and byte(s, index + 4) == 101:
            return index + 5
    if byte(s, index) == 45:
        index = index + 1
    if index >= size:
        return 4294967295
    ch = byte(s, index)
    if ch < 48 or ch > 57:
        return 4294967295
    if ch == 48:
        index = index + 1
    else:
        going = True
        while going and index < size:
            ch = byte(s, index)
            if ch >= 48 and ch <= 57:
                index = index + 1
            else:
                going = False
    if index < size and byte(s, index) == 46:
        index = index + 1
        begin = index
        going = True
        while going and index < size:
            ch = byte(s, index)
            if ch >= 48 and ch <= 57:
                index = index + 1
            else:
                going = False
        if index == begin:
            return 4294967295
    if index < size and (byte(s, index) == 69 or byte(s, index) == 101):
        index = index + 1
        if index < size and (byte(s, index) == 43 or byte(s, index) == 45):
            index = index + 1
        begin = index
        going = True
        while going and index < size:
            ch = byte(s, index)
            if ch >= 48 and ch <= 57:
                index = index + 1
            else:
                going = False
        if index == begin:
            return 4294967295
    return index
'''


def source_program():
    source = integer_source()
    node, = (n for n in ast.parse(source).body if n.name == 'atom')
    old = ast.get_source_segment(source, node)
    assert source.count(old) == 1
    source = source.replace(old, ATOM.strip())
    old = '                            new_node(o, w, kind, index, end - index)'
    new = '''                            if kind == 3:
                                cursor = index
                                while cursor < end:
                                    unit = byte(s, cursor)
                                    if unit == 46 or unit == 69 or unit == 101:
                                        kind = 7
                                    cursor = cursor + 1
                            new_node(o, w, kind, index, end - index)'''
    assert source.count(old) == 1
    source = source.replace(old, new)
    old = 'put(o, 0, 5208772604367785521)'
    assert source.count(old) == 1
    return source.replace(old, 'put(o, 0, ' + str(MAGIC) + ')')


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
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_data_json', 'functions': functions})


if __name__ == '__main__':
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap/agent_data_json.hepta'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)
