"""Generate native service records from complete issued Graph observations."""
from __future__ import annotations
import ast
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT.parent
sys.path.insert(0, str(BASE / 'Hepta-agent-edit-native'))
from hepta.hia_agent_assembly import render_assembly
from hepta.hia_program import verify_program
from tools.generate_hia_selfhost import compact_authoring_cfg, total_scalar_functions
from tools.hia_agent_edit_source_views import CopyBuilder
from tools import generate_hia_agent_edit_apply_graph as graph
from service_records import BODY, CONSTANTS, LITERALS


def source_program():
    labels = {}
    for value in LITERALS:
        raw = value.encode()
        assert len(raw) <= 32
        labels['L_' + value.replace('.', '_').replace('-', '_')] = [len(raw), *(int.from_bytes(raw[i:i + 8], 'little') for i in (0, 8, 16, 24))]
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if node.id in CONSTANTS:
                return ast.copy_location(ast.Constant(CONSTANTS[node.id]), node)
            return node
        def visit_Call(self, node):
            node = self.generic_visit(node)
            args = []
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in labels:
                    args.extend(ast.Constant(v) for v in labels[arg.id])
                else:
                    args.append(arg)
            node.args = args
            return node
    own = Expand().visit(ast.parse(BODY)).body
    path = BASE / 'native-agent-worker-next/tools/generate_hia_worker_report.py'
    spec = importlib.util.spec_from_file_location('frozen_worker_report_authoring', path)
    report = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(report)
    prefix = next(n for n in ast.parse(report.BODY).body if isinstance(n, ast.FunctionDef) and n.name == 'prefix')
    class Limit(ast.NodeTransformer):
        def visit_Constant(self, node):
            return ast.copy_location(ast.Name(id='limit', ctx=ast.Load()), node) if node.value == 4096 else node
    prefix = Limit().visit(prefix)
    prefix.name = 'prefix_limit'
    prefix.args.args.append(ast.arg(arg='limit', annotation=ast.Name(id='u64', ctx=ast.Load())))
    prior = {n.name: n for n in ast.parse(graph.source_program()).body}
    keep = ('gkind', 'amount', 'element', 'text_is', 'field', 'sizes', 'new_node', 'set_edge', 'pair',
            'literal', 'graph_shape', 'clone_graph', 'clone_container', 'clone_scalar', 'word', 'get', 'put')
    return ast.unparse(ast.fix_missing_locations(ast.Module(body=own + [prefix] + [prior[name] for name in keep], type_ignores=[]))) + '\n'


def document():
    nodes = ast.parse(source_program()).body
    names = {n.name: 'f' + str(i + 1) for i, n in enumerate(nodes)}
    signatures = {n.name: ([a.annotation.id for a in n.args.args], n.returns.id) for n in nodes}
    total = total_scalar_functions(nodes)
    params = [{'name': 'v0', 'type': 'readbuf'}, {'name': 'v1', 'type': 'mutbuf'}, {'name': 'v2', 'type': 'mutbuf'}]
    functions = [{'name': 'f0', 'params': params, 'returns': ['u32'], 'effects': ['read', 'write', 'trap'],
        'entry': 'b0', 'blocks': [{'id': 'b0', 'params': params, 'ops': [
            {'op': 'borrow.read', 'args': ['v1'], 'out': [{'name': 'v3', 'type': 'readbuf'}], 'attrs': {}},
            {'op': 'call', 'args': ['v0', 'v3', 'v2'], 'out': [{'name': 'v4', 'type': 'u32'}], 'attrs': {'function': names['service_record']}},
            {'op': 'loan.end', 'args': ['v3'], 'out': [], 'attrs': {}}], 'term': {'op': 'ret', 'values': ['v4']}}]}]
    for node in nodes:
        builder = CopyBuilder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append(dict(name=names[node.name], params=[builder.param(v) for v in builder.params],
            returns=[builder.returns], effects=['read', 'write', 'trap'], entry='b0', blocks=builder.blocks))
    value = compact_authoring_cfg(dict(schema='hepta.hia.program.v8', module='agent_service_records', functions=functions))
    fs = value['functions']
    counts = (len(fs), sum(len(f['blocks']) for f in fs), sum(len(b['ops']) for f in fs for b in f['blocks']),
              max(len(f['blocks']) for f in fs), max(len(b['params']) for f in fs for b in f['blocks']))
    if any(a > b for a, b in zip(counts, (128, 1536, 8192, 256, 16))):
        raise ValueError(dict(original_compiler_limits_exceeded=counts))
    verify_program(value)
    return value


if __name__ == '__main__':
    value = document()
    raw = render_assembly(value).encode()
    target = ROOT / 'examples/hia_bootstrap/agent_service_records.hiaasm'
    target.write_bytes(raw)
    fs = value['functions']
    print(json.dumps(dict(path=str(target), bytes=len(raw), sha256=sha256(raw).hexdigest(), functions=len(fs),
        blocks=sum(len(f['blocks']) for f in fs), instructions=sum(len(b['ops']) for f in fs for b in f['blocks']),
        max_blocks=max(len(f['blocks']) for f in fs), max_block_parameters=max(len(b['params']) for f in fs for b in f['blocks'])), sort_keys=True), flush=True)
