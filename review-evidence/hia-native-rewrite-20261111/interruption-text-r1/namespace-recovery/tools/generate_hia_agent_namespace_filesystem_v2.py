"""Extend the frozen descriptor owner with actual identity observations.

The original fourteen operations retain their exact frames and state changes.
Operation 15 returns the complete Linux x86-64 fstat observation; operation 16
returns the actual effective uid.  Neither primitive admits a namespace root.
That policy belongs to the next HIA namespace coordinator.
"""
from __future__ import annotations

import ast
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_agent_namespace_filesystem import FS, MAGIC
from tools.generate_hia_agent_namespace_objects import ObjectBuilder
from tools.generate_hia_agent_namespace_store import VALUES
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions

ROOT = Path(__file__).resolve().parents[1]


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('frozen filesystem authoring anchor changed: ' + old)
    return source.replace(old, new)


def source_program():
    body = FS
    body = replace_once(body, 'get(w, 48) > 14', 'get(w, 48) > 16')
    body = replace_once(body, 'op > 14', 'op > 16')
    body = replace_once(body, 'if op == 4 or op == 6 or op == 8:',
                        'if op == 4 or op == 6 or op == 8 or op == 15:')
    body = replace_once(body, 'if op == 12:\n        return choose(a == 0',
                        'if op == 12 or op == 16:\n        return choose(a == 0')
    body = replace_once(body, 'elif op == 4:\n        extra = 144',
                        'elif op == 4 or op == 15:\n        extra = 144')
    body = replace_once(body, 'elif op <= 11:\n        index = lookup(w, a)',
                        'elif op <= 11 or op == 15:\n        index = lookup(w, a)')
    body = replace_once(body, '    else:\n        expected = 0\n        if op == 4:',
                        '''    elif op == 16:
        if raw > 4294967295 or n != 0:
            refuse(w, 22)
            return emit(o, w, 4294967293, 0, 0)
        put(w, 176, raw)
    else:
        expected = 0
        if op == 4 or op == 15:''')
    body = replace_once(body, '    if op == 4:\n        return stat_result(s, o, w)',
                        '''    if op == 4:
        return stat_result(s, o, w)
    if op == 15:
        if length(o) < 400:
            refuse(w, 23)
            return emit(o, w, 4294967293, 0, 0)
        complete(o, w, 0, 144)
        copy_input(o, s, 256, 256, 144)
        return 0''')
    body = replace_once(body, '            elif op <= 11:\n                put(o, 64, get(w, 128))',
                        '''            elif op == 16:
                put(o, 64, get(w, 176))
            elif op <= 11 or op == 15:
                put(o, 64, get(w, 128))''')
    return body.replace('FS_MAGIC', str(MAGIC)) + '\n' + VALUES[VALUES.index('\ndef read64('):]


def document():
    nodes = ast.parse(source_program()).body
    names = {node.name: 'f' + str(i) for i, node in enumerate(nodes)}
    if len(names) != len(nodes):
        raise ValueError('duplicate namespace filesystem symbol')
    sig = {node.name: ([a.annotation.id for a in node.args.args], node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = ObjectBuilder(node, names, sig, total)
        builder.statements(node.body)
        functions.append({'name': names[node.name], 'params': [builder.param(v) for v in builder.params],
                          'returns': [builder.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': builder.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': 'agent_namespace_filesystem_v2',
                                  'functions': functions})


if __name__ == '__main__':
    target = ROOT / 'examples/hia_bootstrap/agent_namespace_filesystem_v2.hiaasm'
    target.write_text(render_assembly(document()))
    print(target.name, target.stat().st_size)
