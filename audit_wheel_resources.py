#!/usr/bin/env python3
"""Read every tracked source at an exact commit; export all wheel/resource candidates."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import zlib

HEAD = "7e9c5a796a29746d169f9db97392ec774f627c03"
TREE = "79843bddc6df7306299f0be6475a2fcd187b4d97"
PROTOCOL = "HIA_WHEEL_AUDIT_ZLIB_BASE64"
root = Path(os.environ["GITHUB_WORKSPACE"]) / "source"
out = Path(os.environ["RUNNER_TEMP"]) / "hia-wheel-resource-audit"
out.mkdir(mode=0o700)
os.chdir(root)
started = time.time_ns()

def run(argv):
    p = subprocess.run(argv, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    return {"argv": argv, "returncode": p.returncode,
            "stdout": p.stdout.decode("utf-8", "strict"), "stderr": p.stderr.decode("utf-8", "strict")}

def git_text(*args):
    p = run(["git", *args])
    if p["returncode"] != 0:
        raise RuntimeError(p)
    return p["stdout"].strip()

assert sys.version_info[:3] == (3, 14, 4), sys.version
assert git_text("rev-parse", "HEAD") == HEAD
assert git_text("rev-parse", "HEAD^{tree}") == TREE
assert git_text("write-tree") == TREE
assert git_text("status", "--porcelain=v1", "--untracked-files=all") == ""
listing = subprocess.check_output(["git", "ls-tree", "-rz", "--full-tree", "HEAD"], cwd=root)
entries = []
for record in listing.split(b"\0"):
    if not record:
        continue
    header, path_bytes = record.split(b"\t", 1)
    mode, kind, blob = header.decode("ascii").split(" ")
    path = path_bytes.decode("utf-8", "strict")
    if kind != "blob" or mode not in ("100644", "100755", "120000"):
        raise RuntimeError(("unsupported tracked entry", path, mode, kind))
    if path.startswith("/") or any(x in ("", ".", "..") for x in path.split("/")):
        raise RuntimeError(("unsafe tracked path", path))
    entries.append((path, mode, blob))
assert len(entries) == 3084, len(entries)
assert sum(p.endswith(".py") for p, _, _ in entries) == 1269

def read_entry(path, mode, expected_blob):
    target = root / path
    st = target.lstat()
    if mode == "120000":
        assert stat.S_ISLNK(st.st_mode), path
        raw = os.fsencode(os.readlink(target))
        actual_mode = "120000"
    else:
        assert stat.S_ISREG(st.st_mode) and not target.is_symlink(), path
        raw = target.read_bytes()
        actual_mode = "100755" if st.st_mode & 0o111 else "100644"
    git_blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    assert actual_mode == mode and git_blob == expected_blob, (path, actual_mode, git_blob)
    return raw, {"path": path, "mode": mode, "blob": git_blob, "bytes": len(raw),
                 "sha256": hashlib.sha256(raw).hexdigest()}

rg_pattern = r"DISCOVERY_FILES|NATIVE_SOURCE_FILES|SOURCE_BUILD_FILES|COMPILER_BUILD_FILES|PUBLICATION_BUILD_FILES|bdist_wheel|no-build-isolation|\.whl|wheel"
rg = run(["rg", "--line-number", "--no-heading", "--glob", "*.py", rg_pattern, "."])
assert rg["returncode"] in (0, 1), rg
(out / "rg.stdout.txt").write_text(rg["stdout"], encoding="utf-8")
(out / "rg.stderr.txt").write_text(rg["stderr"], encoding="utf-8")
patterns = {
    "resource_constants": re.compile(r"\b(?:DISCOVERY_FILES|NATIVE_SOURCE_FILES|SOURCE_BUILD_FILES|COMPILER_BUILD_FILES|PUBLICATION_BUILD_FILES)\b"),
    "wheel_or_pip": re.compile(r"wheel|\.whl|\bpip\b|bdist_|no-build-isolation|setuptools", re.IGNORECASE),
    "contract_import": re.compile(r"\bhia_agent_contract\b"),
}
before, candidates, python_inventory, syntax_errors = [], [], [], []
for path, mode, blob in entries:
    raw, meta = read_entry(path, mode, blob)
    before.append(meta)
    if not path.endswith(".py"):
        continue
    item = dict(meta)
    try:
        parsed = ast.parse(raw, filename=path)
        compile(raw, path, "exec", dont_inherit=True)
        methods = []
        for node in ast.walk(parsed):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                signature = ast.dump(node.args, include_attributes=False)
                decorators = [ast.dump(d, include_attributes=False) for d in node.decorator_list]
                assertions = sum(isinstance(n, ast.Assert) or
                                 (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and
                                  n.func.attr.startswith(("assert", "fail", "skipTest")))
                                 for n in ast.walk(node))
                methods.append({"name": node.name, "line": node.lineno,
                                "signature_ast": signature, "decorators_ast": decorators,
                                "assertion_nodes": assertions,
                                "body_ast_sha256": hashlib.sha256(ast.dump(node, include_attributes=False).encode("utf-8")).hexdigest()})
        item.update({"parse": "PASS", "test_methods": methods})
    except (SyntaxError, ValueError, UnicodeError) as exc:
        item.update({"parse": "ERROR", "exception_type": type(exc).__name__, "exception": str(exc)})
        syntax_errors.append(dict(item))
    python_inventory.append(item)
    try:
        content = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise RuntimeError(("non-UTF8 tracked Python source", path)) from exc
    reasons = [name for name, pattern in patterns.items() if pattern.search(content)]
    if reasons:
        candidates.append({**meta, "match_reasons": reasons, "content": content,
                           "parse": item["parse"], "test_methods": item.get("test_methods", [])})

after = [read_entry(*entry)[1] for entry in entries]
assert before == after
assert git_text("rev-parse", "HEAD") == HEAD
assert git_text("rev-parse", "HEAD^{tree}") == TREE
assert git_text("write-tree") == TREE
assert git_text("status", "--porcelain=v1", "--untracked-files=all") == ""
report = {
    "schema": "hia.exact-complete-wheel-resource-audit.v1",
    "status": "READ_ONLY_SCAN_COMPLETE",
    "product_head": HEAD, "product_tree": TREE, "index_tree": TREE,
    "interpreter": sys.version, "executable": sys.executable,
    "started_epoch_ns": started, "finished_epoch_ns": time.time_ns(),
    "tracked_count": len(entries), "python_count": len(python_inventory),
    "candidate_count": len(candidates), "syntax_error_count": len(syntax_errors),
    "all_tracked_bytes_modes_git_blobs_verified": True,
    "source_before_after_equal": True, "clean_worktree_before_after": True,
    "product_mutations": False, "qualification_or_test_execution": False,
    "rg": rg, "tracked_files": before, "python_files": python_inventory,
    "syntax_errors": syntax_errors, "candidates": candidates,
}
raw = (json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
(out / "REPORT.json").write_bytes(raw)
compressed = zlib.compress(raw, 9)
(out / "REPORT.json.zlib").write_bytes(compressed)
encoded = base64.b64encode(compressed).decode("ascii")
chunks = [encoded[i:i+16384] for i in range(0, len(encoded), 16384)]
metadata = {"protocol": PROTOCOL, "payload": "REPORT.json",
            "raw_bytes": len(raw), "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "raw_blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest(),
            "compressed_bytes": len(compressed), "compressed_sha256": hashlib.sha256(compressed).hexdigest(),
            "base64_chars": len(encoded), "chunk_count": len(chunks)}
(out / "EXPORT.json").write_text(json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps({**metadata, "kind": "begin"}, sort_keys=True), flush=True)
for index, chunk in enumerate(chunks):
    print(json.dumps({"protocol": PROTOCOL, "payload": "REPORT.json", "kind": "chunk",
                      "index": index, "data_bytes": len(chunk),
                      "data_sha256": hashlib.sha256(chunk.encode("ascii")).hexdigest(),
                      "data": chunk}, sort_keys=True), flush=True)
print(json.dumps({**metadata, "kind": "end"}, sort_keys=True), flush=True)
print(json.dumps({"status": report["status"], "tracked": len(entries),
                  "python": len(python_inventory), "candidates": len(candidates),
                  "syntax_errors": len(syntax_errors), "source_unchanged": True}), flush=True)
