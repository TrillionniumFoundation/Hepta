"""Private authoring utilities for the complete historical importer."""
from __future__ import annotations
import ast
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = Path(os.environ.get('HIA_BASELINE_ROOT', str(ROOT.parent/'Hepta-v66-restored')))
ORDINARY = ROOT.parent/'native-composite-driver-reconstructed'
sys.path[:0] = [str(ROOT), str(ORDINARY), str(BASE)]
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions


def source(body: str, constants: dict, entry: str) -> str:
    tree = ast.parse(body)
    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node
    tree = ast.fix_missing_locations(Expand().visit(tree))
    fns = {node.name: node for node in tree.body}
    reachable = {entry}; pending = [entry]
    while pending:
        for node in ast.walk(fns[pending.pop()]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in fns and node.func.id not in reachable:
                    reachable.add(node.func.id); pending.append(node.func.id)
    tree.body = [fns[entry]] + [node for node in tree.body if node.name != entry and node.name in reachable]
    return ast.unparse(tree)+'\n'


def document(text: str, module: str):
    nodes = ast.parse(text).body
    names = {node.name:'f'+str(i) for i,node in enumerate(nodes)}
    sigs = {node.name:([p.annotation.id for p in node.args.args],node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes); functions = []
    for node in nodes:
        builder = Builder(node,names,sigs,total); builder.statements(node.body)
        functions.append({'name':names[node.name],'params':[builder.param(p) for p in builder.params],
            'returns':[builder.returns],'effects':['read','write','trap'],'entry':'b0','blocks':builder.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v8','module':module,'functions':functions})


def write_document(doc, name):
    path = ROOT/'examples/hia_bootstrap'/name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_assembly(doc))
    print(path.name,path.stat().st_size)
