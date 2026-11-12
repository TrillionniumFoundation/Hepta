"""Static and pure-controller checks only; never run a source child or owner."""
from __future__ import annotations
import ast
from hashlib import sha1, sha256
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
S2 = HERE.parent / "core-numeric-source83-on-v89-r2"
OLD = HERE.parent / "core-numeric-v88-integration-r1"

def require(value, message):
    if not value:
        raise ValueError(message)

def pin(raw):
    return dict(size=len(raw), sha256=sha256(raw).hexdigest(),
                git_blob_sha1=sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest())

def isolated_definition(filename, name, namespace):
    module = ast.parse((HERE / filename).read_bytes(), filename=filename)
    node = next(x for x in module.body if isinstance(x, ast.FunctionDef) and x.name == name)
    isolated = ast.Module(body=[node], type_ignores=[])
    exec(compile(isolated, filename, "exec"), namespace)
    return namespace[name]

def main():
    policy = json.loads((HERE / "POLICY.json").read_bytes())
    old_policy = json.loads((HERE / "reference/POLICY.json").read_bytes())
    projection = json.loads((HERE / "MECHANICAL-PROJECTIONS.json").read_bytes())
    result = []
    for name in ("files.py", "adapt_request.py", "finalize.py", "diagnostics.py"):
        current = (HERE / name).read_bytes()
        expected = next(x for x in policy["adapter_inputs"] if x["name"] == name)
        assert pin(current) == {k: expected[k] for k in ("size", "sha256", "git_blob_sha1")}
        original = (HERE / "reference" / name).read_bytes()
        original_pin = next(x for x in old_policy["adapter_inputs"] if x["name"] == name)
        assert pin(original) == {k: original_pin[k] for k in ("size", "sha256", "git_blob_sha1")}
        text = current.decode()
        for row in reversed([r for r in projection["projections"] if r["file"] == name]):
            assert text.count(row["new_text"]) == row["count"]
            text = text.replace(row["new_text"], row["old_text"])
        assert text.encode() == original
        ast.parse(current, filename=name)
        result.append({"check": "exact_adapter_reverse_projection_and_parse", "file": name, "pin": pin(current)})
    workflow = (HERE / "workflow.template.yml").read_text()
    reversed_workflow = workflow
    for row in reversed([r for r in projection["projections"] if r["file"] == "workflow.template.yml"]):
        assert reversed_workflow.count(row["new_text"]) == row["count"]
        reversed_workflow = reversed_workflow.replace(row["new_text"], row["old_text"])
    assert reversed_workflow == (HERE / "reference/workflow.yml").read_text()
    assert workflow.count("uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262") == 3
    assert workflow.count("uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1") == 1
    assert workflow.count("uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02") == 1
    assert workflow.count('unset LD_LIBRARY_PATH') == 4 and "python-version: '3.14.4'" in workflow
    assert workflow.count("@@ADAPTER_COMMIT@@") == 5
    result.append({"check": "workflow_exact_reverse_projection_and_fixed_actions", "pass": True})
    request = json.loads((S2 / "REQUEST.json").read_bytes())
    old_request = json.loads((OLD / "REQUEST.json").read_bytes())
    expected_ids = request["expected_ids"]
    assert len(expected_ids) == len(set(expected_ids)) == 83 and expected_ids == old_request["expected_ids"]
    assert request["test_classes"] == old_request["test_classes"]
    assert request["class_denominators"] == old_request["class_denominators"]
    assert request["generator_names"] == old_request["generator_names"] and len(request["generator_names"]) == 62
    assert request["derivations"] == old_request["derivations"] and len(request["derivations"]) == 4
    assert request["qualification_seconds"] == 180 and request["cleanup_seconds"] == 3
    assert request["native_and_compiler_and_subprocess_entry_poison_required_in_each_source_child"] is True
    assert request["minimum_available_bytes"] == 536870912 and request["minimum_available_inodes"] == 4096
    for expected in policy["original_controls"]:
        raw = (S2 / "control" / expected["name"]).read_bytes()
        assert pin(raw) == {k: expected[k] for k in ("size", "sha256", "git_blob_sha1")}
        ast.parse(raw, filename=expected["name"])
        if expected["name"] != "launch.py":
            assert raw == (OLD / "control" / expected["name"]).read_bytes()
    worker = (S2 / "control/worker.py").read_bytes()
    for item in policy["worker_metadata_substitutions"]:
        assert worker.count(item["old_text"].encode()) == 1
        worker = worker.replace(item["old_text"].encode(), item["new_text"].encode(), 1)
    assert pin(worker) == {k: policy["adapted_worker"][k] for k in ("size", "sha256", "git_blob_sha1")}
    result.append({"check": "original83_62_and_three_controls_and_all_limits", "pass": True})
    assert len(request["source_files"]) == 1653 and sum(row["size"] for row in request["source_files"]) == 40186814
    assert len({row["relative_path"] for row in request["source_files"]}) == 1653
    assert policy["physical_source_count"] == 1653 and policy["physical_source_bytes"] == 40186814
    delta = json.loads((S2 / "SOURCE-DELTA.json").read_bytes())
    assert len(delta["delta"]) == 4 and len({row["path"] for row in delta["delta"]}) == 4
    assert policy["source_delta_sha256"] == sha256((S2 / "SOURCE-DELTA.json").read_bytes()).hexdigest()
    assert policy["source_controls_request_sha256"] == sha256((S2 / "REQUEST.json").read_bytes()).hexdigest()
    assert policy["base_tree_metadata_sha256"] == sha256((S2 / "BASE-GIT-TREE.json").read_bytes()).hexdigest()
    assert request["base_commit"] == policy["base_commit"] == "cc51db1c74c082572ae6183ebfa0c81cd36b0648"
    assert request["base_tree"] == policy["base_tree"] == "01bcbef40c31bd9aaf9f359ffca4ffa557fc8cd3"
    assert request["virtual_source_tree_before_derivation"] == policy["prospective_tree_before_derivation"] == "4e59cae3f3c498980bb347694be78043e8115e3f"
    patterns = policy["sparse_checkout"]["patterns"]
    for row in request["source_files"]:
        absolute = "/" + row["relative_path"]
        assert any(absolute == prefix or absolute.startswith(prefix + "/") for prefix in patterns)
    result.append({"check": "all1653_paths_and_four_overlay_hashes_and_sparse_coverage", "pass": True})
    specs = isolated_definition("finalize.py", "command_specs", {"require": require})(request)
    assert len(specs) == len({x[0] for x in specs}) == 71
    operation = Path("/fixed/source83-operation")
    new_targets = isolated_definition("diagnostics.py", "targets", {"require": require})(operation)
    old_node = next(x for x in ast.parse((HERE / "reference/diagnostics.py").read_bytes()).body
                    if isinstance(x, ast.FunctionDef) and x.name == "targets")
    namespace = {"require": require}
    exec(compile(ast.Module(body=[old_node], type_ignores=[]), "original-targets", "exec"), namespace)
    original_targets = namespace["targets"](operation)
    inserted = new_targets[4:10]
    assert new_targets[:4] + new_targets[10:] == original_targets
    assert len(new_targets) == len({str(row[1]) for row in new_targets}) == 34
    assert [row[0] for row in inserted] == [
        "generator-32-report", "generator-32-stdout", "generator-32-stderr",
        "generator-45-report", "generator-45-stdout", "generator-45-stderr"]
    for offset, number in ((0,32),(3,45)):
        label = specs[number-1][0]
        for row, suffix in zip(inserted[offset:offset+3], (".report.json",".stdout.log",".stderr.log"), strict=True):
            assert row[1] == operation / "actual-source/evidence" / (label + suffix) and row[2] is True
    assert policy["failure_custody"]["fixed_small_targets"] == 34
    assert policy["failure_custody"]["stdout_raw_cap_bytes"] == 524288
    assert policy["failure_custody"]["stdout_total_cap_bytes"] == 1048576
    result.append({"check": "pure_target_function_mapping_old28_order_and_new6_closed_flags", "pass": True})
    launch = ast.parse((S2 / "control/launch.py").read_bytes())
    main_node = next(x for x in launch.body if isinstance(x, ast.FunctionDef) and x.name == "main")
    guarded = next(x for x in main_node.body if isinstance(x, ast.Try))
    final_if = next(x for x in guarded.finalbody if isinstance(x, ast.If))
    assert isinstance(final_if.test, ast.Name) and final_if.test.id == "closed"
    glob_calls = lambda nodes: [x for n in nodes for x in ast.walk(n)
        if isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and x.func.attr == "rglob"]
    assert len(glob_calls(final_if.body)) == 1 and not glob_calls(final_if.orelse)
    assert len(glob_calls(main_node.body)) == 1
    result.append({"check": "launcher_static_child_traversal_only_under_closed", "pass": True})
    observation = {"schema": "hepta.hia.numeric-source83-actions-r2-static-checks.v1",
        "status": "STATIC_AND_PURE_CONTROLLER_CHECKS_PASS", "checks": result,
        "source83_executed": False, "generators_executed": False, "owner_executed": False,
        "native_executed": False, "whole_failure_injection_claimed": False,
        "source_control_denominator_unchanged": 83,
        "pure_functions_executed": ["finalize.command_specs", "old diagnostics.targets", "new diagnostics.targets"],
        "runtime_scope": "Local CPython3.12.14 AST/metadata checks only; actual3.14.4 request unexecuted."}
    with (HERE / "STATIC-CHECKS.json").open("x") as output:
        json.dump(observation, output, sort_keys=True, indent=2)
        output.write("\n")
    print(json.dumps({"status": observation["status"], "checks": len(result),
        "source_methods_executed": 0, "generator_commands_executed": 0}, sort_keys=True))

if __name__ == "__main__":
    main()
