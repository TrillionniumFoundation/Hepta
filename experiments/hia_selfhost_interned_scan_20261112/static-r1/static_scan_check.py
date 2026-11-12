"""Read only exact source bytes and Python ASTs; never import project modules."""
from __future__ import annotations
import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys

TARGETS = ("check_graph", "loan_access", "loan_borrow", "loan_transfer", "owner_free")
TOKEN = re.compile(r"@[^@\n]+@")

def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def read(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("fixed input must be regular, independent file")
    data = path.read_bytes()
    after = path.lstat()
    fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, k) != getattr(after, k) for k in fields) or len(data) != before.st_size:
        raise ValueError("fixed input identity changed during read")
    return data

def save(path, data):
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    if read(path) != data:
        raise ValueError("static output readback differs")

def function(source, name):
    matches = list(re.finditer(r"(?m)^def " + re.escape(name) + r"\(", source))
    if len(matches) != 1:
        raise ValueError("expected exactly one authoring function: " + name)
    begin = matches[0].start()
    match = re.search(r"(?m)^def ", source[matches[0].end():])
    if match is None:
        raise ValueError("missing following function delimiter: " + name)
    end = matches[0].end() + match.start()
    return begin, end, source[begin:end]

def parse_function(body):
    # Token spelling is irrelevant to AST shape; no substitutions are executed.
    tree = ast.parse(TOKEN.sub("0", body))
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
        raise ValueError("isolated authoring AST differs")
    return tree.body[0]

def calls(node):
    return sorted({n.func.id for n in ast.walk(node)
                   if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)})

def count_of(node, kind):
    return sum(isinstance(n, kind) for n in ast.walk(node))

def numbered_occurrences(source, pattern):
    return [{"line": i, "text": line} for i, line in enumerate(source.splitlines(), 1)
            if re.search(pattern, line)]

def restore_function(name, body):
    if name == "check_graph":
        body = body.replace("    scan_limit = 0\n", "", 1)
        body = body.replace("            scan_limit = get(w, 480)\n", "", 1)
        body = body.replace("while i < scan_limit:", "while i < 2048:", 1)
    else:
        body = body.replace("    scan_limit = get(w, 480)\n", "", 1)
        body = body.replace("while i < scan_limit", "while i < 2048", 1)
    return body

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    manifest_raw = read(root / "INPUT-PINS.json")
    manifest = json.loads(manifest_raw)
    if manifest["five_functions"] != list(TARGETS):
        raise ValueError("changed target denominator")
    raw_by_path = {}
    parse_rows = []
    for pin in manifest["source_pins"]:
        raw = read(root / "baseline" / pin["path"])
        if (len(raw), sha(raw), git_blob(raw)) != (pin["bytes"], pin["sha256"], pin["git_blob"]):
            raise ValueError("baseline source mismatch: " + pin["path"])
        raw_by_path[pin["path"]] = raw
        if pin["path"].endswith(".py"):
            ast.parse(raw, filename=pin["path"])
            parse_rows.append(pin["path"])
    baseline = raw_by_path["tools/generate_hia_selfhost.py"].decode("utf-8")
    candidate_raw = read(root / manifest["candidate"]["path"])
    candidate_pin = manifest["candidate"]
    if (len(candidate_raw), sha(candidate_raw), git_blob(candidate_raw)) != (
            candidate_pin["bytes"], candidate_pin["sha256"], candidate_pin["git_blob"]):
        raise ValueError("candidate differs from immutable pre-read source")
    candidate = candidate_raw.decode("utf-8")
    ast.parse(candidate, filename=manifest["candidate"]["path"])
    rows = []
    inverse = candidate
    expected_body_calls = {
        "check_graph": {"get", "put"},
        "loan_access": {"get", "loan_live", "fail"},
        "loan_borrow": {"get", "loan_live", "loan_ancestor", "fail"},
        "loan_transfer": {"get", "loan_live", "owner_type", "loan_argument"},
        "owner_free": {"get", "loan_live", "fail"},
    }
    for name in TARGETS:
        before_begin, _, before = function(baseline, name)
        after_begin, after_end, after = function(candidate, name)
        restored = restore_function(name, after)
        if restored != before:
            raise ValueError("unlisted function change: " + name)
        inverse = inverse.replace(after, before, 1)
        old_ast, new_ast = parse_function(before), parse_function(after)
        old_loops = [n for n in ast.walk(old_ast) if isinstance(n, ast.While)
                     and isinstance(n.test, (ast.Compare, ast.BoolOp))
                     and "2048" in ast.unparse(n.test)]
        new_loops = [n for n in ast.walk(new_ast) if isinstance(n, ast.While)
                     and "scan_limit" in ast.unparse(n.test)]
        if len(old_loops) != 1 or len(new_loops) != 1:
            raise ValueError("loop denominator changed: " + name)
        old_loop, new_loop = old_loops[0], new_loops[0]
        if ast.dump(ast.Module(body=old_loop.body, type_ignores=[])) != ast.dump(
                ast.Module(body=new_loop.body, type_ignores=[])):
            raise ValueError("loop body changed: " + name)
        if set(calls(ast.Module(body=old_loop.body, type_ignores=[]))) != expected_body_calls[name]:
            raise ValueError("unreviewed loop body helper: " + name)
        assignments = [n for n in ast.walk(new_ast) if isinstance(n, ast.Assign)
                       and any(isinstance(x, ast.Name) and x.id == "scan_limit" for x in n.targets)]
        if len(assignments) != (2 if name == "check_graph" else 1):
            raise ValueError("scan bound assignment denominator")
        rows.append({
            "name": name,
            "baseline_line": baseline[:before_begin].count("\n") + 1,
            "candidate_line": candidate[:after_begin].count("\n") + 1,
            "before_sha256": sha(before.encode()),
            "after_sha256": sha(after.encode()),
            "loop_body_ast_equal": True,
            "loop_body_calls": calls(ast.Module(body=new_loop.body, type_ignores=[])),
            "new_bound_assignments": len(assignments),
            "new_bound_rhs": [ast.unparse(n.value) for n in assignments],
            "original_condition": ast.unparse(old_loop.test),
            "candidate_condition": ast.unparse(new_loop.test),
        })
    if inverse != baseline:
        raise ValueError("whole source differs outside five functions")
    # The following functions are outside the patch and retain their original
    # error, initialization, capacity and probe policy exactly.
    preserved_generator = [
        "compile", "parse_function", "define", "variable", "fail", "get", "put",
        "resource_type", "owner_type", "loan_live", "loan_ancestor",
        "loan_argument", "parse_params", "parse_block", "instruction",
        "source_program",
    ]
    for name in preserved_generator:
        if function(baseline, name)[2] != function(candidate, name)[2]:
            raise ValueError("preserved helper changed: " + name)
    if (len(re.findall(r"while i < 2048", baseline)),
            len(re.findall(r"while i < 2048", candidate))) != (6, 1):
        raise ValueError("fixed loops outside intended five changed")
    if "while cursor != 0 and depth < 2048:" not in candidate:
        raise ValueError("ancestor bound changed")
    names = raw_by_path["tools/hia_selfhost_names.py"].decode()
    for exact in ("while probes < 2048:", "if index >= 2048:",
                  "slot = (slot + 1) & 2047", "put(w, 480, index + 1)"):
        if exact not in names:
            raise ValueError("interner admission/probing changed")
    tests = []
    for path, raw in raw_by_path.items():
        if not path.startswith("tests/"):
            continue
        tree = ast.parse(raw, filename=path)
        if any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == "load_tests"
               for n in tree.body):
            raise ValueError("test custom loader needs independent inventory")
        classes = []
        for cls in tree.body:
            if not isinstance(cls, ast.ClassDef):
                continue
            methods = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")]
            if methods:
                ids = [path.replace("/", ".")[:-3] + "." + cls.name + "." + n.name for n in methods]
                classes.append({"name": cls.name, "source_order_ids": ids, "unittest_name_order_ids": sorted(ids)})
        tests.append({"path": path, "classes": classes,
                      "method_count": sum(len(x["source_order_ids"]) for x in classes)})
    if sum(t["method_count"] for t in tests) != 110:
        raise ValueError("planned original method inventory changed")
    count_mentions = {}
    for path, raw in raw_by_path.items():
        if path.startswith("tools/"):
            hits = numbered_occurrences(raw.decode(), r"\b480\b")
            if hits:
                count_mentions[path] = hits
    if set(count_mentions) != {"tools/generate_hia_selfhost.py", "tools/hia_selfhost_names.py"}:
        raise ValueError("additional count references require review")
    report = {
        "schema": "hia.selfhost.interned-scan-static-check.v1",
        "status": "STATIC_BYTES_AND_AST_VERIFIED_NOT_GENERATED_OR_PRODUCT_TESTED",
        "python": {"implementation": platform.python_implementation(),
                   "version": platform.python_version(), "executable": sys.executable},
        "input_manifest_sha256": sha(manifest_raw),
        "checker_sha256": sha(read(Path(__file__).resolve())),
        "baseline": manifest["baseline_generator"],
        "candidate": candidate_pin,
        "python_ast_parsed_files": parse_rows + [manifest["candidate"]["path"]],
        "whole_source_inverse_exact": True,
        "five_loops": rows,
        "unchanged_functions": preserved_generator,
        "original_test_method_count": 110,
        "original_test_ids": tests,
        "literal_count_references_in_read_source_closure": count_mentions,
        "source_inputs_rechecked_after_static_analysis": True,
        "scope": {
            "project_imports": False, "generated_source": False,
            "core_validation": False, "native_execution": False,
            "unittest_collection_or_execution": False,
            "new_profile": False, "performance_estimate": False,
        },
    }
    for path, raw in raw_by_path.items():
        if read(root / "baseline" / path) != raw:
            raise ValueError("source drift at end")
    if read(root / manifest["candidate"]["path"]) != candidate_raw:
        raise ValueError("candidate drift at end")
    save(root / "EXACT-DIFF.patch", "".join(difflib.unified_diff(
        baseline.splitlines(keepends=True), candidate.splitlines(keepends=True),
        fromfile="a/tools/generate_hia_selfhost.py", tofile="b/tools/generate_hia_selfhost.py")).encode())
    save(root / "ORIGINAL-TEST-INVENTORY.json", wire(tests))
    save(root / "STATIC-OBSERVATIONS.json", wire(report))
    print(json.dumps({"status": report["status"], "five_loops": len(rows),
                      "test_ids": 110, "report_sha256": sha(wire(report))}, sort_keys=True))

if __name__ == "__main__":
    main()
