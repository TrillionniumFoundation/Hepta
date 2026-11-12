"""Build the bounded-read A2 publication delta without executing any product."""
import ast
from hashlib import sha1, sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PREFIX = "experiments/hia_bounded_read_owner_20261112/actions-native-development-r1/"


def identity(local):
    raw = (ROOT / local).read_bytes()
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest(),
            "sha": sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def write_json(path, value):
    (ROOT / path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


old_tree = ast.parse((ROOT / "authoring/unexecuted-A1/native_support.py").read_bytes())
new_tree = ast.parse((ROOT / "control/native_support.py").read_bytes())
assert len(old_tree.body) == len(new_tree.body)
changed_nodes = []
for old, new in zip(old_tree.body, new_tree.body):
    if ast.dump(old, include_attributes=False) != ast.dump(new, include_attributes=False):
        assert isinstance(old, ast.FunctionDef) and isinstance(new, ast.FunctionDef)
        assert old.name == new.name == "observe_compiler_bundle"
        changed_nodes.append(old.name)
assert changed_nodes == ["observe_compiler_bundle"]

old_policy = json.loads((ROOT / "authoring/unexecuted-A1/policy.json").read_bytes())
new_policy = json.loads((ROOT / "control/policy.json").read_bytes())
assert set(old_policy) == set(new_policy)
assert all(old_policy[key] == new_policy[key] for key in old_policy if key != "controls")
assert set(old_policy["controls"]) == set(new_policy["controls"])
changed_controls = sorted(name for name in old_policy["controls"]
                          if old_policy["controls"][name] != new_policy["controls"][name])
assert changed_controls == ["control-manifest.json", "native_support.py"]

old_plan = json.loads((ROOT / "authoring/publish-plan.json").read_bytes())
changed = []
for prior in old_plan:
    actual = identity(prior["local"])
    if actual["sha"] != prior["sha"]:
        changed.append(dict(actual, local=prior["local"], path=prior["path"],
                            mode="100644", type="blob", previous_sha=prior["sha"]))
expected_changed = {
    "control/DESIGN.json", "control/native_support.py", "control/control-manifest.json",
    "control/policy.json", "authoring/compiler_lineage.inc", "authoring/write_design.py",
    "authoring/AST-PARSE-ACTIONS.json",
}
assert {row["local"] for row in changed} == expected_changed

controls_report = json.loads((ROOT / "authoring/receipt-join-controls-r2/report.json").read_bytes())
assert controls_report["status"] == "PASS"
assert controls_report["expected_ids"] == controls_report["executed_ids"]
assert len(controls_report["cases"]) == 10
assert all(row["status"] == "PASS" for row in controls_report["cases"])
assert controls_report["native_executed"] is False
assert controls_report["product_cases_executed"] == 0

write_json("authoring/RECEIPT-DELTA-CHECK-R2.json", {
    "schema": "hepta.hia.bounded-read-receipt-delta-local-check.v1",
    "status": "PASS_STATIC_DELTA_AND_TEN_SYNTHETIC_READER_CONTROLS",
    "source_candidate": old_policy["candidate"]["commit"],
    "source_tree": old_policy["candidate"]["tree"],
    "changed_runtime_ast_nodes": changed_nodes,
    "changed_control_pins": changed_controls,
    "unchanged_policy_fields_except_controls": sorted(key for key in old_policy if key != "controls"),
    "changed_existing_files": changed,
    "unchanged_existing_files": len(old_plan) - len(changed),
    "synthetic_report": identity("authoring/receipt-join-controls-r2/report.json"),
    "product_or_compiler_execution": False,
    "workflow_triggered": False,
    "original_limits_or_population_changed": False,
})

new_paths = {
    "control/RECEIPT-JOIN-REVISION-R2.json": "RECEIPT-JOIN-REVISION-R2.json",
    "authoring/receipt_join_controls_r2.py": "authoring/receipt_join_controls_r2.py",
    "authoring/build_revision2_plan.py": "authoring/build_revision2_plan.py",
    "authoring/RECEIPT-DELTA-CHECK-R2.json": "evidence/RECEIPT-DELTA-CHECK-R2.json",
    "authoring/RECEIPT-DELTA-CHECK-R2-initial-error.json":
        "evidence/RECEIPT-DELTA-CHECK-R2-initial-error.json",
    "authoring/receipt-join-controls-r2/report.json": "evidence/receipt-joins-r2/report.json",
    "authoring/receipt-join-controls-r2/member-manifest.json": "evidence/receipt-joins-r2/member-manifest.json",
    "authoring/receipt-join-controls-r2/synthetic-originals.tar.xz.base64.txt":
        "evidence/receipt-joins-r2/synthetic-originals.tar.xz.base64.txt",
}
plan = changed + [dict(identity(local), local=local, path=PREFIX + relative,
                       mode="100644", type="blob", previous_sha=None)
                  for local, relative in new_paths.items()]
plan.sort(key=lambda row: row["path"])
write_json("authoring/publish-plan-r2.json", plan)
print(json.dumps({"files": len(plan), "changed": len(changed), "new": len(new_paths),
                  "bytes": sum(row["bytes"] for row in plan),
                  "changed_runtime_function": changed_nodes}))
