"""Independent HIA authoring and original compiler limits for diagnostics."""
import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent / 'Hepta-v66-restored'
sys.path[:0] = [str(ROOT), str(BASE)]
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions


class DiagnosticBuilder(Builder):
    def expr(self, node):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'copy_range':
            values = [self.expr(arg) for arg in node.args]
            assert len(values) == 5 and values[0][1] == 'mutbuf' and values[1][1] == 'readbuf'
            return self.op('buffer.copy_range', values[:2] + [self.cast(v, 'usize') for v in values[2:]])
        return super().expr(node)


def document(text, module, two_read=False):
    nodes = ast.parse(text).body
    names = {n.name: 'f' + str(i + int(two_read)) for i, n in enumerate(nodes)}
    sigs = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    if two_read:
        params = [{'name': 'v0', 'type': 'readbuf'}, {'name': 'v1', 'type': 'mutbuf'}, {'name': 'v2', 'type': 'mutbuf'}]
        functions.append({'name': 'f0', 'params': params, 'returns': ['u32'],
            'effects': ['read', 'write', 'trap'], 'entry': 'b0', 'blocks': [{'id': 'b0', 'params': params,
            'ops': [{'op': 'borrow.read', 'args': ['v1'], 'out': [{'name': 'v3', 'type': 'readbuf'}], 'attrs': {}},
                    {'op': 'call', 'args': ['v0', 'v3', 'v2'], 'out': [{'name': 'v4', 'type': 'u32'}], 'attrs': {'function': names[nodes[0].name]}},
                    {'op': 'loan.end', 'args': ['v3'], 'out': [], 'attrs': {}}],
            'term': {'op': 'ret', 'values': ['v4']}}]})
    for node in nodes:
        b = DiagnosticBuilder(node, names, sigs, total)
        b.statements(node.body)
        functions.append({'name': names[node.name], 'params': [b.param(v) for v in b.params],
                          'returns': [b.returns], 'effects': ['read', 'write', 'trap'],
                          'entry': 'b0', 'blocks': b.blocks})
    return compact_authoring_cfg({'schema': 'hepta.hia.program.v8', 'module': module, 'functions': functions})


def write(text, name, two_read=False):
    doc = document(text, name, two_read)
    path = ROOT / 'examples/hia_bootstrap' / (name + '.hiaasm')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_assembly(doc))
    print(name, len(doc['functions']), sum(len(f['blocks']) for f in doc['functions']),
          sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']), path.stat().st_size)
    return doc
