"""Fixed original NDU cost/response policy, for independent qualification only.

The complete source is an immutable historical Git blob. Only its original
pure policy definitions are compiled here. Product code never imports this
module, and no executable, transport, solver or ranking entry is constructed.
"""
from __future__ import annotations
import ast
from hashlib import sha256
import json
from pathlib import Path
import re
from types import SimpleNamespace

SELF = Path(__file__)
SELF_RAW = SELF.read_bytes()
SELF_NAME = "tools/hia_ndu_policy_reference.py"
FIXTURE = "tests/fixtures/hia_ndu_fixed_policy_original_v1/optimizer.py.txt"
ORIGINAL_COMMIT = "d45bd45658d8b9b1147683496750e9609c5be672"
ORIGINAL_PATH = "hepta/hia_ndu_optimizer.py"
ORIGINAL_SHA256 = "5f3ad958cd3ec6cd10bae46782685fdb2789eb0635646a4ebb3493fac05d2e45"
FUNCTIONS = ("_reject", "_integer", "ns_to_ms_q32", "_unique_object", "_json",
             "_validate_native_rank_response")
CONSTANTS = ("_HEX", "_MAX_INT")


def policy_namespace(root=None, *, take=None):
    root = SELF.resolve(strict=True).parents[1] if root is None else Path(root)
    take = Path.read_bytes if take is None else take
    if SELF.read_bytes() != SELF_RAW:
        raise ValueError("executed NDU qualification reference changed")
    paths = (root / SELF_NAME, root / FIXTURE)
    captured = {path: take(path) for path in paths}
    if captured[paths[0]] != SELF_RAW:
        raise ValueError("NDU qualification reference selected another implementation")
    raw = captured[paths[1]]
    if sha256(raw).hexdigest() != ORIGINAL_SHA256:
        raise ValueError("complete original NDU policy source differs")
    text = raw.decode("utf-8")
    tree = ast.parse(text)
    selected = []
    functions = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "OptimizationRejected":
            selected.append(node)
        elif isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS:
            selected.append(node)
            functions[node.name] = ast.get_source_segment(text, node) + "\n"
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in CONSTANTS:
                selected.append(node)
    if set(functions) != set(FUNCTIONS) or len(selected) != 9:
        raise ValueError("complete original NDU policy definitions differ")
    namespace = {"__builtins__": __builtins__, "json": json, "re": re, "sha256": sha256}
    exec(compile(ast.Module(body=selected, type_ignores=[]),
                 str(paths[1]), "exec"), namespace)

    def unchanged():
        if SELF.read_bytes() != SELF_RAW:
            raise ValueError("executed NDU qualification reference changed")
        if any(take(path) != value for path, value in captured.items()):
            raise ValueError("NDU original policy capture changed")
    unchanged()
    return SimpleNamespace(namespace=namespace, functions=functions, unchanged=unchanged,
                           source_sha256=ORIGINAL_SHA256, original_commit=ORIGINAL_COMMIT,
                           **{name: namespace[name] for name in (*FUNCTIONS, "OptimizationRejected")})
