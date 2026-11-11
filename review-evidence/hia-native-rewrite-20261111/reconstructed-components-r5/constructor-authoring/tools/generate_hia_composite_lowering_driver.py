"""Author the complete composite continuation controllers as native HIA.

RECONSTRUCTED-DEVELOPMENT-r1. Authoring remains Python; the emitted continuation
decisions are HIA. These files do not expose a production selector or declare
whole-native qualification. The separate exact semantic kernels are reused.
"""
from __future__ import annotations
import ast
import importlib
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
BASELINE = Path(os.environ.get("HIA_BASELINE_ROOT", str(ROOT))).resolve()
if BASELINE != ROOT:
    sys.path.insert(1, str(BASELINE))

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_selfhost import Builder, compact_authoring_cfg, total_scalar_functions
from tools.hia_composite_lowering_driver_common import CONSTANTS, COMMON

MODULES = {
    "ctor": "tools.hia_composite_constructor_driver",
    "main": "tools.hia_composite_lowering_driver_main",
    "services": "tools.hia_composite_lowering_driver_services",
    "stream": "tools.hia_composite_lowering_driver_stream",
}
ENTRIES = {"ctor": "constructor_driver", "main": "lower_main", "services": "lower_services", "stream": "lower_stream"}


def source_program(kernel: str) -> str:
    if kernel not in MODULES:
        raise ValueError("unknown complete lowering controller")
    selected = importlib.import_module(MODULES[kernel])
    shared = importlib.import_module(MODULES["main"])
    bodies = selected.BODY + "\n" + COMMON
    if kernel != "main":
        bodies += "\n" + shared.BODY
    constants = dict(CONSTANTS)
    constants.update(getattr(shared, "CONSTANTS", {}))
    constants.update(getattr(selected, "CONSTANTS", {}))

    class Expand(ast.NodeTransformer):
        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]), node)
            return node

    tree = ast.fix_missing_locations(Expand().visit(ast.parse(bodies)))
    functions = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef) or node.name in functions:
            raise ValueError("authoring contains a duplicate or nonfunction declaration")
        functions[node.name] = node
    reachable, queue = {ENTRIES[kernel]}, [ENTRIES[kernel]]
    while queue:
        for node in ast.walk(functions[queue.pop()]):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                name = node.func.id
                if name in functions and name not in reachable:
                    reachable.add(name)
                    queue.append(name)
    first = functions[ENTRIES[kernel]]
    tree.body = [first] + [node for node in tree.body
                           if node.name in reachable and node is not first]
    return ast.unparse(tree) + "\n"


def document(kernel: str) -> dict:
    nodes = ast.parse(source_program(kernel)).body
    names = {node.name: "f" + str(index) for index, node in enumerate(nodes)}
    signatures = {node.name: ([arg.annotation.id for arg in node.args.args],
                              node.returns.id) for node in nodes}
    total = total_scalar_functions(nodes)
    functions = []
    for node in nodes:
        builder = Builder(node, names, signatures, total)
        builder.statements(node.body)
        functions.append({
            "name": names[node.name],
            "params": [builder.param(param) for param in builder.params],
            "returns": [builder.returns],
            "effects": ["read", "write", "trap"],
            "entry": "b0", "blocks": builder.blocks,
        })
    return compact_authoring_cfg({
        "schema": "hepta.hia.program.v8",
        "module": "composite_lowering_driver_" + kernel,
        "functions": functions,
    })


def main() -> None:
    kernels = sys.argv[1:] or list(MODULES)
    for kernel in kernels:
        target = ROOT / ("examples/hia_bootstrap/composite_lowering_driver_" + kernel + ".hiaasm")
        target.parent.mkdir(parents=True, exist_ok=True)
        assembly = render_assembly(document(kernel))
        target.write_text(assembly, encoding="utf-8")
        print(target.name, target.stat().st_size)


if __name__ == "__main__":
    main()
