"""Inventory the exact retained HIA source and hosted callers without executing it.

This is a static migration inventory, not a semantic, release or deletion gate.
It never changes defaults, removes a file or promotes historical test results.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from hashlib import sha256
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def git(*args: str) -> str:
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True)


def module_name(path: str) -> str:
    name = path.removesuffix(".py").replace("/", ".")
    return name.removesuffix(".__init__")


def python_record(path: str, raw: bytes) -> dict:
    tree = ast.parse(raw, filename=path)
    package = module_name(path).rpartition(".")[0]
    if path.endswith("/__init__.py"):
        package = module_name(path)
    imports: set[str] = set()
    strings: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            target = node.module or ""
            if node.level:
                levels = package.split(".")
                prefix = levels[:len(levels) - node.level + 1]
                target = ".".join([*prefix, *([target] if target else [])])
            if target:
                imports.add(target)
                imports.update(target + "." + alias.name for alias in node.names
                               if alias.name != "*")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.add(node.value)
    public = [node.name for node in tree.body
              if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
              and not node.name.startswith("_")]
    return {
        "module": module_name(path),
        "purpose": (ast.get_docstring(tree) or "").split("\n\n", 1)[0],
        "top_level_public_definitions": public,
        "imports": sorted(imports),
        "literal_hia_paths": sorted(s for s in strings
                                    if s.endswith((".hia", ".hiaasm")) and "\n" not in s),
        "literal_native_selectors": sorted(s for s in strings
                                           if s.startswith("HEPTA_HIA_") and "\n" not in s),
        "lines": len(raw.splitlines()),
    }


def inventory(excluded: set[str]) -> dict:
    names = sorted(set(git("ls-files", "-z").split("\0")) - {""} - excluded)
    ledger = []
    python = {}
    for name in names:
        path = ROOT / name
        if not path.is_file() or path.is_symlink():
            ledger.append({"path": name, "kind": "missing_or_nonregular",
                           "bytes": None, "sha256": None})
            continue
        raw = path.read_bytes()
        ledger.append({"path": name, "kind": path.suffix or "extensionless",
                       "bytes": len(raw), "sha256": sha256(raw).hexdigest()})
        if name.endswith(".py"):
            python[name] = python_record(name, raw)
    modules = {row["module"]: path for path, row in python.items()}
    callers = defaultdict(set)
    for path, row in python.items():
        for target in row["imports"]:
            # A from-import may name a symbol, so use its longest known module.
            parts = target.split(".")
            while parts:
                candidate = ".".join(parts)
                if candidate in modules:
                    if modules[candidate] != path:
                        callers[modules[candidate]].add(path)
                    break
                parts.pop()
    for path, row in python.items():
        row["repository_static_callers"] = sorted(callers[path])
    package = []
    for path, row in python.items():
        if path.startswith("hepta/"):
            package.append({
                "path": path, **row,
                "retained_language": "Python",
                "whole_module_native_replacement_qualified": False,
                "deletion_authorized_by_this_inventory": False,
                "coverage_note": "Static import/literal edges only; dynamic and external callers require review.",
            })
    return {
        "schema": "hepta.hia.native-rewrite-inventory.v1",
        "status": "STATIC_INVENTORY_NOT_NATIVE_DELIVERY_ACCEPTANCE",
        "git_head": git("rev-parse", "HEAD").strip(),
        "git_head_tree": git("rev-parse", "HEAD^{tree}").strip(),
        "index_vs_head_changed_paths": git("diff", "--cached", "--name-only").splitlines(),
        "worktree_vs_index_changed_paths": git("diff", "--name-only").splitlines(),
        "scope": {
            "members": "Git index paths; current worktree bytes",
            "excluded_report_paths": sorted(excluded),
            "all_retained_python_parsed": True,
            "every_line_semantically_audited": False,
            "dynamic_caller_closure_established": False,
            "independent_reference_tests_replaced": False,
            "live_worker_migrated": False,
        },
        "counts": {
            "files": len(ledger), "python_files": len(python),
            "production_python_modules": len(package),
            "hia_assembly_files": sum(x["kind"] == ".hiaasm" for x in ledger),
            "hia_json_source_files": sum(x["kind"] == ".hia" for x in ledger),
            "files_by_extension": dict(sorted(Counter(x["kind"] for x in ledger).items())),
        },
        "package_modules": package,
        "hosted_tools": [{"path": p, **r} for p, r in python.items() if p.startswith("tools/")],
        "files": ledger,
        "claims": {
            "whole_native_delivery_qualified": False,
            "old_stack_can_be_removed": False,
            "historical_tests_relabelled": False,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    excluded = {"docs/HIA_NATIVE_REWRITE_INVENTORY.json", "docs/HIA_NATIVE_REWRITE_STATUS_20261111.md"}
    if output.is_relative_to(ROOT):
        excluded.add(output.relative_to(ROOT).as_posix())
    result = inventory(excluded)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(output), "status": result["status"], "counts": result["counts"]}, sort_keys=True))


if __name__ == "__main__":
    main()
