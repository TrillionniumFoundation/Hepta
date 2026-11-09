"""Discover every current HIA unittest module; retain failures and platform gaps.

Unlike the narrower unified-candidate gate, this inventory is derived from all
live tests/test_hia*.py files plus shared Core acceptance modules. Source identity
covers every tracked file in the exact checkout. No skip is promoted to a pass,
no failed test is removed, and finite tests do not establish a whole-stack rewrite.
"""
from __future__ import annotations

import argparse
import ast
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools.qualify_hia_direct_native import Result, _ids


def git(*args):
    result = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, check=True)
    return result.stdout


def snapshot():
    if Path(os.fsdecode(git("rev-parse", "--show-toplevel")).strip()).resolve() != ROOT:
        raise ValueError("full inventory requires its exact checkout root")
    files = {}
    for name in sorted(os.fsdecode(p) for p in git("ls-files", "-z").split(b"\0") if p):
        path = ROOT / name
        if path.is_symlink():
            data, kind = os.fsencode(os.readlink(path)), "symlink-target"
        else:
            data, kind = path.read_bytes(), "file"
        files[name] = {"kind": kind, "sha256": sha256(data).hexdigest(), "bytes": len(data)}
    raw = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return {"sha256": sha256(raw).hexdigest(), "files": files}


def inventory():
    rows = []
    for path in sorted(set((ROOT / "tests").glob("test_hia*.py"))
                       | set((ROOT / "tests").glob("test_core_seven_shared*.py"))):
        data = path.read_bytes()
        row = {"path": path.relative_to(ROOT).as_posix(), "module": "tests." + path.stem,
               "sha256": sha256(data).hexdigest()}
        try:
            tree = ast.parse(data, filename=str(path))
            row["static_test_methods"] = sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                and n.name.startswith("test_") for n in ast.walk(tree))
        except SyntaxError as exc:
            # Unittest will retain this as a real module-load error as well.
            row["syntax_error"] = str(exc)
        rows.append(row)
    return rows


def qualify():
    started = time.monotonic_ns()
    before = snapshot()
    initial_status = os.fsdecode(git("status", "--porcelain", "--untracked-files=all"))
    modules = inventory()
    suite = unittest.defaultTestLoader.loadTestsFromNames([row["module"] for row in modules])
    expected = _ids(suite)
    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2, resultclass=Result).run(suite)
    after = snapshot()
    final_status = os.fsdecode(git("status", "--porcelain", "--untracked-files=all"))
    complete = (len(expected) == len(set(expected))
                and sorted(result.executed_ids) == sorted(expected))
    stable = before == after
    gaps = bool(result.skipped or result.expectedFailures)
    failed = bool(result.failures or result.errors or result.unexpectedSuccesses
                  or not stable or initial_status or final_status)
    ok = not failed and not gaps and complete
    return {"schema": "hepta.hia.full-test-inventory.v1",
        "status": "FULL_HIA_TESTS_PASS" if ok else "FAIL" if failed else "OPEN_TEST_OR_PLATFORM_GAPS",
        "ok": ok, "completed_utc": datetime.now(timezone.utc).isoformat(),
        "elapsed_ns": time.monotonic_ns() - started,
        "git_head": os.fsdecode(git("rev-parse", "HEAD")).strip(),
        "git_tree": os.fsdecode(git("rev-parse", "HEAD^{tree}")).strip(),
        "git_status_before": initial_status, "git_status_after": final_status,
        "host": {"platform": platform.platform(), "python": sys.version},
        "source": before, "source_unchanged": stable,
        "module_inventory": modules, "modules_total": len(modules),
        "static_test_methods": sum(row.get("static_test_methods", 0) for row in modules),
        "test_inventory": expected, "tests_run": result.testsRun, "executed_ids": result.executed_ids,
        "inventory_complete": complete, "case_counts": result.case_counts,
        "failures": [{"id": t.id(), "traceback": trace} for t, trace in result.failures],
        "errors": [{"id": t.id(), "traceback": trace} for t, trace in result.errors],
        "skipped": [{"id": t.id(), "reason": reason} for t, reason in result.skipped],
        "expected_failures": [{"id": t.id(), "traceback": trace} for t, trace in result.expectedFailures],
        "unexpected_successes": [t.id() for t in result.unexpectedSuccesses],
        "claims": {"whole_stack_rewritten_in_hia": False, "all_input_correctness_proved": False,
                   "all_platforms_qualified": False, "non_HIA_repository_tests_included": False},
        "notes": ["AST method counts are static inventory, not executed-case counts",
                  "class-setup failures/skips can prevent expected test IDs from starting",
                  "all skipped and expected-failure records remain open, not passes",
                  "shared Core acceptance modules are included explicitly"]}


def normalize_report_path(value, root=ROOT):
    requested = Path(value).absolute()
    # Inspect the supplied spelling before resolve erases links. Then resolve
    # dot-dot segments before testing whether output is inside the checkout.
    if requested.exists() or any(p.is_symlink() for p in (requested, *requested.parents)):
        raise ValueError("report requires a new nonsymlink output path")
    output = requested.resolve()
    if output.is_relative_to(Path(root).resolve()):
        raise ValueError("report must be outside the exact source checkout")
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = normalize_report_path(args.output)
    report = qualify()
    with output.open("x") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({k: report[k] for k in ("status", "modules_total", "static_test_methods", "tests_run",
                                            "inventory_complete", "source_unchanged")}))
    raise SystemExit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
