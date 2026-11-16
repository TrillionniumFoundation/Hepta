#!/usr/bin/env python3
"""Stdlib text/AST verification only. Never import or run the original observer."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import sys


def pin(data):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main():
    root = Path(__file__).resolve().parent
    cases_raw = (root / "cases.json").read_bytes()
    document = json.loads(cases_raw)
    cases = document["cases"]
    assert len(cases) == document["finite_case_count"] == 248
    assert len({case["id"] for case in cases}) == 248
    assert len({case["template"] for case in cases}) == document["template_count"] == 21
    assert document["reconstruction_not_recovered_old_270"] is True
    assert all(set(case) == {"id", "template", "method", "settings", "outer_exception", "fault"} for case in cases)
    assert all(type(case["outer_exception"]) is bool for case in cases)
    for false, true in zip(cases[::2], cases[1::2]):
        assert false["outer_exception"] is False and true["outer_exception"] is True
        assert false["id"].endswith(".outer0") and true["id"] == false["id"][:-1] + "1"
        assert {k: v for k, v in false.items() if k not in ("id", "outer_exception")} == {
            k: v for k, v in true.items() if k not in ("id", "outer_exception")}
    identities = json.loads((root / "source-identity.json").read_bytes())
    for name, expected in identities["actual_sources"].items():
        assert pin((root / "originals" / name).read_bytes()) == expected
    text = (root / "originals/hepta/hia_slot_ledger_native.py").read_text()
    module = ast.parse(text)
    cls = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == "NativeSlotLedgerStore")
    methods = [node.name for node in cls.body if isinstance(node, ast.FunctionDef)]
    assert methods == document["methods"] and len(methods) == 15
    assert pin((root / "originals/NativeSlotLedgerStore.py.txt").read_bytes()) == identities["class"]
    original_helper_names = set(identities["helpers"])
    assert original_helper_names == {"_custody", "request_packet", "_text", "_untext", "_decimal",
                                    "_raise", "_SelectedRendererFailure", "_claimed_artifact_wire"}
    for name, expected in identities["helpers"].items():
        actual = pin((root / expected["path"]).read_bytes())
        assert actual == {key: expected[key] for key in ("bytes", "sha256")}
    source_nodes = {node.name: node for node in module.body
                    if isinstance(node, (ast.ClassDef, ast.FunctionDef))}
    lines = text.splitlines(keepends=True)
    for name, expected in identities["helpers"].items():
        node = source_nodes[name]
        start = min([node.lineno] + [d.lineno for d in node.decorator_list])
        raw = "".join(lines[start - 1:node.end_lineno]).encode()
        assert raw == (root / expected["path"]).read_bytes()
    sql = json.loads((root / "sql-sites.json").read_bytes())
    assert len(sql) == 15 and [row["id"] for row in sql] == document["sql_sites"]
    sql_calls = sorted((node for node in ast.walk(cls)
                        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "_execute" and len(node.args) >= 2
                        and isinstance(node.args[1], ast.Constant)
                        and isinstance(node.args[1].value, str)),
                       key=lambda node: (node.lineno, node.col_offset))
    assert len(sql_calls) == 15
    for row, call in zip(sql, sql_calls):
        assert row["line"] == call.lineno
        assert row["call_source"] == ast.get_source_segment(text, call)
        assert row["statement"] == call.args[1].value
    sql_faults = [c for c in cases if c["id"].startswith(("fault.before.", "fault.after."))]
    assert len(sql_faults) == 60
    for site in document["sql_sites"]:
        for boundary in ("before", "after"):
            subset = [c for c in sql_faults if c["fault"]["event"] == "sql." + site + "." + boundary]
            assert len(subset) == 2 and {c["outer_exception"] for c in subset} == {False, True}
    paths = ("observe_originals.py", "run_originals_twice.py", "static_check.py")
    trees = {path: ast.parse((root / path).read_text(), filename=path) for path in paths}
    observer = trees["observe_originals.py"]
    direct_imports = []
    for node in observer.body:
        if isinstance(node, ast.Import):
            direct_imports.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            direct_imports.append(node.module)
    assert not set(direct_imports) & {"hepta", "tools", "ctypes", "sqlite3", "subprocess"}
    frozen = next(node.value for node in observer.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == "FROZEN_NAMES" for target in node.targets))
    assert set(ast.literal_eval(frozen)) == original_helper_names | {"NativeSlotLedgerStore"}
    assert "NativeSlotLedger" not in ast.literal_eval(frozen)
    fake_provider_classes = {node.name for node in observer.body if isinstance(node, ast.ClassDef)}
    assert {"FakeCTypes", "FakeOS", "FakeUUID", "DB", "Store", "Cursor", "Subject", "World"} <= fake_provider_classes
    # Observer class definitions are module-level; provider calls do not create
    # dynamic user types or reset any original code object.
    assert not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                   and node.func.attr == "replace" for node in ast.walk(observer))
    assert not any(isinstance(node, ast.ClassDef) for top in observer.body
                   if isinstance(top, (ast.FunctionDef, ast.ClassDef))
                   for node in ast.walk(top) if node is not top)
    supervisor = trees["run_originals_twice.py"]
    constants = {target.id: ast.literal_eval(node.value)
                 for node in supervisor.body if isinstance(node, ast.Assign)
                 for target in node.targets if isinstance(target, ast.Name)
                 and target.id in ("TIMEOUT_SECONDS", "CLEANUP_SECONDS")}
    assert constants == {"TIMEOUT_SECONDS": 180, "CLEANUP_SECONDS": 5}
    plan = json.loads((root / "port-map.json").read_bytes())
    assert [mode["name"] for mode in plan["all_15_modes"]] == methods
    assert len(plan["primitive_kinds"]) == 46
    assert plan["callbacks_to_retained_15_methods_in_selected_mode"] == 0
    controls = json.loads((root / "resource-controls.json").read_bytes())
    assert len(controls["controls"]) == controls["count"] == 14
    assert len({row["id"] for row in controls["controls"]}) == 14
    callers = json.loads((root / "caller-plan.json").read_bytes())
    assert {name: group["count"] for name, group in callers["groups"].items()} == {
        "ordinary_112": 112, "separate_128": 128, "shared_complete_components_152": 152,
        "slot_complete_15": 15, "slot_complete_integration_13": 13,
        "store_complete_130": 130, "transaction_61": 61}
    assert all(len(group["ordered_ids"]) == group["count"] for group in callers["groups"].values())
    assert callers["original_transaction61_outer_seconds"] == 1800
    assert len(callers["groups"]["slot_complete_integration_13"]["retained_nested_10_ordered_ids"]) == 10
    print(json.dumps({
        "schema": "hepta.slot-sql.reconstruction-static-review.r1",
        "status": "STATIC_CHECKS_PASS_NOT_EXECUTED",
        "python": sys.version, "cases": 248, "base_templates": 21, "modes": 15, "SQL_sites": 15,
        "cases_with_declared_fault": sum(c["fault"] is not None for c in cases),
        "resource_control_plans": 14, "primitive_kinds": 46,
        "original_class_and_helpers_equal_frozen_sources": True,
        "original_test_whole_sha256": identities["actual_sources"]["tests/test_hia_slot_ledger_native.py"]["sha256"],
        "new_source_pins": {path: pin((root / path).read_bytes()) for path in paths},
        "original_or_candidate_methods_executed": 0, "product_imports": 0,
        "SQL_VM_Native_tests_generators_compilers_executed": 0,
        "not_a_runtime_or_refinement_qualification": True,
    }, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
