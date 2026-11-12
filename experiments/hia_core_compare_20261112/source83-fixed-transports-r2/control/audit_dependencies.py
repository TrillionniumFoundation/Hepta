"""Static inventory of the frozen 62 authoring entries and selected 83 methods."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = Path("/workspace/scratch/e26ed3e2edcf/core-numeric-v88-integration-r1/source")
REQUEST = BASE.parent / "REQUEST.json"


def pin(path, raw):
    return {"path": path, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "git_blob_sha1": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def name_of(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = name_of(node.value)
        return parent + "." + node.attr if parent else node.attr
    return ""


def scoped_calls(statements):
    found = []
    class Read(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            return
        visit_AsyncFunctionDef = visit_FunctionDef
        def visit_ClassDef(self, node):
            return
        def visit_Call(self, node):
            found.append(node)
            self.generic_visit(node)
    reader = Read()
    for statement in statements:
        reader.visit(statement)
    return found


def direct_inventory(path):
    raw = (BASE / path).read_bytes()
    tree = ast.parse(raw)
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    roots = {name_of(call.func) for call in scoped_calls(tree.body)}
    edges = {name: {name_of(call.func) for call in scoped_calls(node.body)}
             for name, node in functions.items()}
    reached = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        reached.add(name)
        pending.extend(edges.get(name, ()))
    subprocess_calls = []
    for scope, statements in [("<module>", tree.body)] + [(name, node.body) for name, node in functions.items()]:
        for call in scoped_calls(statements):
            target = name_of(call.func)
            if target.startswith(("subprocess.", "os.system", "os.popen", "os.exec", "os.spawn", "os.posix_spawn")):
                subprocess_calls.append({
                    "scope": scope, "line": call.lineno, "target": target,
                    "arguments": ast.unparse(call.args[0]) if call.args else None,
                    "in_direct_local_main_closure": scope == "<module>" or scope in reached,
                })
    return {"file": pin(path, raw), "local_entry_roots": sorted(roots),
            "reached_local_functions": sorted(reached & functions.keys()),
            "external_process_calls": subprocess_calls}


def main():
    request_raw = REQUEST.read_bytes()
    request = json.loads(request_raw)
    names = request["generator_names"]
    if len(names) != 62 or len(set(names)) != 62 or request["expected_methods"] != 83:
        raise ValueError("frozen denominator differs")
    entries = []
    for index, name in enumerate(names, 1):
        row = direct_inventory("tools/generate_hia_" + name + ".py")
        row.update(index=index, name=name)
        entries.append(row)
    test_files = []
    ids = []
    forbidden_oracle_references = []
    for qualified in request["test_classes"]:
        module, cls = qualified.rsplit(".", 1)
        path = module.replace(".", "/") + ".py"
        raw = (BASE / path).read_bytes()
        tree = ast.parse(raw)
        owner = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == cls)
        methods = sorted(node.name for node in owner.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"))
        ids.extend(qualified + "." + method for method in methods)
        references = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Name, ast.Attribute)) and name_of(node).split(".")[-1] in {"assembled_template", "assembled_bridge"}:
                references.append({"line": node.lineno, "name": name_of(node)})
            if isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name in {"assembled_template", "assembled_bridge"}:
                        references.append({"line": node.lineno, "name": alias.name})
        forbidden_oracle_references.extend({"path": path, **row} for row in references)
        test_files.append({"file": pin(path, raw), "class": cls, "methods": methods, "oracle_references": references})
    if ids != request["expected_ids"]:
        raise ValueError("selected test IDs differ")
    if forbidden_oracle_references:
        raise ValueError("selected source module refers to an external assembler oracle")
    reachable = [row["index"] for row in entries if any(item["in_direct_local_main_closure"] for item in row["external_process_calls"])]
    if reachable != [32, 45]:
        raise ValueError("direct external authoring closure differs")
    payload = {
        "schema": "hepta.hia.source83-fixed-transport-dependency-audit.v1",
        "status": "STATIC_INVENTORY_PASS",
        "request": pin(str(REQUEST), request_raw),
        "generator_count": 62, "expected_method_count": 83,
        "generators": entries, "selected_source_classes": test_files,
        "reachable_external_process_generator_indices": reachable,
        "external_process_definition_only_generator_indices": [
            row["index"] for row in entries if row["external_process_calls"]
            and not any(item["in_direct_local_main_closure"] for item in row["external_process_calls"])
        ],
        "selected_source_oracle_references": forbidden_oracle_references,
        "limitations": [
            "The call graph is a static direct-local main closure, not a proof for arbitrary dynamic Python dispatch.",
            "The 62 generators and 83 test methods were not executed by this audit.",
            "Existing module 50 assembled_bridge is an independent assembler oracle; its main/template use literal BRIDGE.",
            "The new original-body assembled_template functions are not selected by any of the frozen 83 source modules.",
            "The unchanged Popen poison remains the actual execution boundary in the next source qualification.",
        ],
    }
    output = ROOT / "DEPENDENCY-AUDIT.json"
    with output.open("xb") as stream:
        stream.write((json.dumps(payload, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"status": payload["status"], "generators": len(entries), "methods": len(ids),
                      "reachable_external": reachable, "definition_only": payload["external_process_definition_only_generator_indices"],
                      "oracle_references": forbidden_oracle_references}))


if __name__ == "__main__":
    main()

