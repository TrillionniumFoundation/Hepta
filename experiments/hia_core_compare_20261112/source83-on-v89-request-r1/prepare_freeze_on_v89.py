"""Freeze cc51 plus four approved transport repairs; metadata and AST only."""
from __future__ import annotations
import ast
import difflib
from hashlib import sha1, sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / "root/numeric-on-v89-source-r1/source"
OLD = HERE.parent / "core-numeric-v88-integration-r1"
REPAIR = HERE.parent / "core-numeric-source83-generator-repair-r2/inputs"
SOURCE = HERE / "source"
NAMES = (
    "tools/generate_hia_artifact_publication.py",
    "tools/generate_hia_release_install.py",
    "tests/test_hia_artifact_publication_native.py",
    "tests/test_hia_release_install.py",
)
EXPECTED = {
    NAMES[0]: (25233, "e2dd15e8bc8d73004bf7ce78f6f2934bf95004a25d1bf41cf89ce3d18b29b8a3"),
    NAMES[1]: (26250, "44b358d1cb5c93621c3db03892b66d802734454f38c24ed91b815becec385018"),
    NAMES[2]: (19531, "1f4b2bc818a77b66ca7838e250a335e3118e4a8db919018900bf2367200d8383"),
    NAMES[3]: (24450, "8c3e28072838ba29004edb955fc95849274eb00e2945a6a9e408e0a130b62333"),
}

def raw_digest(raw):
    return {"size": len(raw), "sha256": sha256(raw).hexdigest(),
            "git_blob_sha1": sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}

def save(name, value):
    with (HERE / name).open("x") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")

def tree_hash(leaves):
    root = {}
    for row in leaves:
        node = root
        parts = row["path"].split("/")
        for name in parts[:-1]:
            node = node.setdefault(name, {})
        assert parts[-1] not in node
        node[parts[-1]] = row
    def walk(node):
        items = []
        for name, value in node.items():
            directory = "sha" not in value
            mode = "40000" if directory else value["mode"]
            digest = walk(value) if directory else value["sha"]
            items.append((name + ("/" if directory else ""),
                mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(digest)))
        raw = b"".join(part for _, part in sorted(items))
        return sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return walk(root)

def main():
    metadata = json.loads((HERE / "BASE-GIT-TREE.json").read_bytes())
    assert metadata["commit"] == "cc51db1c74c082572ae6183ebfa0c81cd36b0648"
    assert metadata["tree"] == tree_hash(metadata["leaves"]) == "01bcbef40c31bd9aaf9f359ffca4ffa557fc8cd3"
    assert len(metadata["leaves"]) == 4097
    expected_tree = {row["path"]: row for row in metadata["leaves"]}
    materialization = json.loads((BASE.parent / "MATERIALIZATION.json").read_bytes())
    assert materialization["commit"] == metadata["commit"] and materialization["tree"] == metadata["tree"]
    assert materialization["files"] == len(materialization["records"]) == 1653
    for name in ("child.py", "common.py", "launch.py", "worker.py"):
        raw = (OLD / "control" / name).read_bytes()
        with (HERE / "control" / name).open("xb") as output:
            output.write(raw)
    spec = importlib.util.spec_from_file_location("source83_frozen_file_metadata", HERE / "control/common.py")
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    baseline = common.snapshot(BASE)
    assert len(baseline) == 1653 and sum(row["size"] for row in baseline) == 40167129
    observed_materialization = {row["path"]: row for row in materialization["records"]}
    assert set(observed_materialization) == {row["relative_path"] for row in baseline}
    for row in baseline:
        name = row["relative_path"]
        original = expected_tree[name]
        assert row["git_blob_sha1"] == original["sha"] == observed_materialization[name]["sha"]
        assert row["size"] == original["size"] == observed_materialization[name]["size"]
        assert row["sha256"] == observed_materialization[name]["sha256"]
        assert format(stat.S_IFREG | row["mode"], "o") == original["mode"]
    SOURCE.mkdir(mode=0o700)
    for row in baseline:
        name = row["relative_path"]
        target = SOURCE / name
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = (BASE / name).read_bytes()
        assert raw_digest(raw)["git_blob_sha1"] == row["git_blob_sha1"]
        with target.open("xb") as output:
            output.write(raw)
        target.chmod(row["mode"])
    differences = []
    for name in NAMES:
        old = (SOURCE / name).read_bytes()
        raw = (REPAIR / name).read_bytes()
        assert (len(raw), sha256(raw).hexdigest()) == EXPECTED[name]
        (SOURCE / name).write_bytes(raw)
        target = HERE / "inputs" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as output:
            output.write(raw)
        differences.extend(difflib.unified_diff(old.decode().splitlines(keepends=True),
            raw.decode().splitlines(keepends=True), fromfile="cc51/" + name, tofile="fixed/" + name))
    after = common.snapshot(SOURCE)
    contents = common.content(after)
    virtual = dict(expected_tree)
    delta = []
    for row in contents:
        name = row["relative_path"]
        old = expected_tree[name]
        mode = format(stat.S_IFREG | row["mode"], "o")
        new = dict(path=name, type="blob", mode=mode, sha=row["git_blob_sha1"], size=row["size"])
        virtual[name] = new
        if any(old[key] != new[key] for key in ("sha", "mode", "size")):
            delta.append(dict(path=name, before=old, after=dict(new, sha256=row["sha256"])))
    assert len(after) == 1653 and sum(row["size"] for row in after) == 40186814
    assert len(delta) == 4 and {row["path"] for row in delta} == set(NAMES)
    assert tree_hash(list(virtual.values())) == "4e59cae3f3c498980bb347694be78043e8115e3f"
    old_request = json.loads((OLD / "REQUEST.json").read_bytes())
    assert old_request["expected_methods"] == 83 and len(old_request["generator_names"]) == 62
    ids, counts = [], []
    for cls_name in old_request["test_classes"]:
        module, cls = cls_name.rsplit(".", 1)
        name = Path(*module.split(".")).with_suffix(".py").as_posix()
        original_raw = (BASE / name).read_bytes()
        assert (SOURCE / name).read_bytes() == original_raw
        node = next(item for item in ast.parse(original_raw, filename=name).body
                    if isinstance(item, ast.ClassDef) and item.name == cls)
        methods = sorted(item.name for item in node.body
                         if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"))
        counts.append({"class": cls_name, "count": len(methods)})
        ids.extend(cls_name + "." + method for method in methods)
    assert ids == old_request["expected_ids"] and counts == old_request["class_denominators"]
    workflow = (SOURCE / ".github/workflows/hia-core.yml").read_text()
    generators = re.search(r"for component in ([^;]+); do", workflow).group(1).split()
    assert generators == old_request["generator_names"] and len(generators) == 62
    assert workflow.count("python-version: '3.14.4'") == 2
    for name in NAMES:
        ast.parse((SOURCE / name).read_bytes(), filename=name)
    controls = [common.pin(path) for path in sorted((HERE / "control").glob("*.py"))]
    for actual, expected in zip(controls, old_request["control_inputs"], strict=True):
        assert {key: actual[key] for key in ("size", "sha256", "git_blob_sha1")} == {
            key: expected[key] for key in ("size", "sha256", "git_blob_sha1")}
        ast.parse(Path(actual["path"]).read_bytes(), filename=actual["path"])
    runtime = common.pin(Path(sys.executable).resolve(strict=True))
    owner = common.pin(SOURCE / "tools/hia_selfhost_process_owner.py")
    assert owner["sha256"] == "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2"
    request = dict(old_request)
    request.update(revision="r3-on-v89-fixed-syscall-transports-actions-template",
        status="FROZEN_UNEXECUTED", base_commit=metadata["commit"], base_tree=metadata["tree"],
        base_full_leaf_count=4097, source_root=str(SOURCE),
        physical_source_count=1653, physical_source_bytes=40186814,
        virtual_source_tree_before_derivation=tree_hash(list(virtual.values())),
        evidence_root=str(HERE / "unexecuted-local-template-only"),
        runtime=runtime, process_owner=owner, control_inputs=controls, source_files=contents)
    allowed_changes = {"revision", "base_commit", "base_tree", "base_full_leaf_count", "source_root",
        "physical_source_count", "physical_source_bytes", "virtual_source_tree_before_derivation",
        "evidence_root", "runtime", "process_owner", "control_inputs", "source_files"}
    assert all(request[key] == old_request[key] for key in old_request if key not in allowed_changes)
    assert common.content(common.snapshot(BASE)) == common.content(baseline)
    save("REQUEST.json", request)
    save("SOURCE-DELTA.json", {"base_commit": metadata["commit"], "base_tree": metadata["tree"],
        "pure_product_commit": "545e7814b97bc767a15810dd99534aaccc23adf4",
        "virtual_tree": request["virtual_source_tree_before_derivation"], "full_virtual_leaf_count": 4097,
        "derived_documents_still_base_bytes_until_the_single_source_run": True,
        "delta_count": 4, "delta": delta})
    save("SOURCE-PHYSICAL-PINS.json", after)
    save("BASE-MATERIALIZATION.json", materialization)
    save("EXPECTED-SOURCE-IDS.json", {"classes": counts, "expected_ids": ids, "method_count": 83,
        "original_numeric_methods": 11, "new_integration_methods": 9,
        "new_lifecycle_methods": 6, "existing_other_source_methods": 57})
    save("STATIC-CHECKS.json", {"status": "STATIC_METADATA_AND_AST_ONLY",
        "base_git_full_tree_recomputed": metadata["tree"], "base_physical_files": 1653,
        "base_physical_files_read_bytewise": True, "base_preserved": True,
        "pure_product_tree_recomputed": request["virtual_source_tree_before_derivation"],
        "exact_four_product_changes": list(NAMES), "full83_modules_unchanged_from_cc51": True,
        "exact83_ids_equal_original": True, "original4_controls_byte_equal": True,
        "all62_names_and_order_equal_original": True, "derive_and_idempotence_four_commands_unchanged": True,
        "source_methods_executed": 0, "generators_executed": 0, "native_executed": False,
        "actual_Source4_scope": "Separate Root-run CPython3.12.14 four controls only.",
        "actual_Source4_canonical": "972b7d6ac850d99262cd928168bfc6eb82c0d97f",
        "prior_source83_failure_not_upgraded": True,
        "local_runtime_is_only_template_metadata": True,
        "new_actual_runtime_required": "CPython3.14.4 on new isolated Actions runner."})
    with (HERE / "SOURCE-DELTA.diff").open("x") as output:
        output.writelines(differences)
    save("LAUNCH.json", {"schema": "hepta.hia.core-compare-integration-source-launch.v1",
        "operation": "UNEXECUTED_TEMPLATE_ONLY_ADAPT_TO_NEW_ACTIONS_RUN",
        "request": common.pin(HERE / "REQUEST.json"),
        "command": [runtime["path"], "-I", "-S", "-B", str(HERE / "control/launch.py")],
        "cwd": str(HERE), "qualification_seconds": 180, "cleanup_seconds": 3,
        "local_execution_authorized": False, "new_Actions_runtime_binding_required": True})
    print(json.dumps({"status": "STATIC_FROZEN_UNEXECUTED", "source_count": len(after),
        "source_bytes": request["physical_source_bytes"], "delta_count": len(delta),
        "source_methods": len(ids), "generators": len(generators),
        "request": raw_digest((HERE / "REQUEST.json").read_bytes()),
        "virtual_tree": request["virtual_source_tree_before_derivation"]}, sort_keys=True))

if __name__ == "__main__":
    main()
