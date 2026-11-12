"""Freeze this small, new, unexecuted four-control request."""
from __future__ import annotations
import ast
import hashlib
import json
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = Path("/workspace/scratch/e26ed3e2edcf/root/numeric-on-v89-source-r1/source")
sys.path.insert(0, str(ROOT / "control"))
import files


def raw_pin(path):
    _, pin = files.read(path)
    return pin


def compact(pin):
    return {key: pin[key] for key in ("path", "size", "sha256", "git_blob_sha1", "mode")}


def write(path, data):
    raw = (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()
    return files.put(path, raw, mode=0o644)


def main():
    source_record, _, source_record_pin = files.json_read(BASE.parent / "MATERIALIZATION.json")
    if (source_record["commit"], source_record["tree"], source_record["files"]) != (
            "cc51db1c74c082572ae6183ebfa0c81cd36b0648",
            "01bcbef40c31bd9aaf9f359ffca4ffa557fc8cd3", 1653):
        raise ValueError("fixed readonly partial-source base differs")
    source_pins = []
    actual_paths = sorted(str(path.relative_to(BASE)) for path in BASE.rglob("*") if path.is_file())
    if actual_paths != [row["path"] for row in source_record["records"]]:
        raise ValueError("source physical file set differs")
    for row in source_record["records"]:
        observed = raw_pin(BASE / row["path"])
        if (observed["size"], observed["sha256"], observed["git_blob_sha1"], observed["mode"]) != (
                row["size"], row["sha256"], row["sha"], int(row["mode"], 8) & 0o777):
            raise ValueError("source file differs: " + row["path"])
        source_pins.append(compact(observed))
    own = []
    for path in sorted(ROOT.rglob("*")):
        if path.is_file():
            own.append(compact(raw_pin(path)))
    runtime_path = Path(sys.executable).resolve(strict=True)
    runtime = raw_pin(runtime_path)
    if sys.version_info[:3] != (3, 12, 14) or runtime["sha256"] != "fa67443527ed9647f760d807e2a38f26340757123e643c4639cf273ed15d5ea7":
        raise ValueError("observed source4-only local runtime differs")
    owner = raw_pin(BASE / "tools/hia_selfhost_process_owner.py")
    if owner["sha256"] != "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2":
        raise ValueError("original owner changed")
    node = ast.parse((ROOT / "control/source_controls.py").read_bytes())
    cls = next(item for item in node.body if isinstance(item, ast.ClassDef) and item.name == "FixedTransportSourceTests")
    expected = ["__main__.FixedTransportSourceTests." + name for name in sorted(
        item.name for item in cls.body if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"))]
    if len(expected) != 4:
        raise ValueError("source4 method set differs")
    all_pins = {row["path"]: row for row in source_pins + own}
    all_pins[owner["path"]] = owner
    all_pins[runtime["path"]] = runtime
    actual = ROOT / "actual-source4-r2"
    if actual.exists():
        raise ValueError("new request requires a never-used actual root")
    request = {
        "schema": "hepta.hia.fixed-transport-source4-request.v1", "status": "UNEXECUTED",
        "qualification_seconds": 180, "cleanup_seconds": 3,
        "minimum_available_bytes": 536870912, "minimum_available_inodes": 4096,
        "expected_methods": 4, "expected_ids": expected,
        "runtime": runtime, "runtime_version": sys.version,
        "runtime_scope": "Observed local CPython 3.12.14 only; not remote3.14.4 qualification",
        "owner": owner, "source_root": str(BASE), "source_record": source_record_pin,
        "source_commit": source_record["commit"], "source_tree": source_record["tree"],
        "physical_source_files": 1653, "full_git_checkout_claimed": False,
        "worker": str(ROOT / "control/source_controls.py"),
        "actual_root": str(actual), "prelaunch_hold": str(ROOT / "SOURCE4-PRELAUNCH-HOLD.json"),
        "control_pins": [row for row in own if "/control/" in row["path"]],
        "input_pins": sorted(all_pins.values(), key=lambda row: row["path"]),
        "source83_executed": False, "native_executed": False, "assembler_oracle_executed": False,
        "original_generator_denominator": 62, "original_source_method_denominator": 83,
        "anticipated_evidence_upper_estimate_bytes": 8 * 1024 * 1024,
        "estimate_is_not_a_product_or_output_cap": True,
    }
    request_pin = write(ROOT / "SOURCE4-REQUEST.json", request)
    launch = {
        "schema": "hepta.hia.fixed-transport-source4-launch.v1", "status": "UNEXECUTED",
        "command": [str(runtime_path), "-I", "-S", "-B", str(ROOT / "control/launch_source4.py"),
                    request_pin["path"], request_pin["sha256"]],
        "cwd": str(ROOT), "request": request_pin,
        "qualification_seconds": 180, "cleanup_seconds": 3,
        "native_executed": False, "source83_executed": False,
    }
    launch_pin = write(ROOT / "SOURCE4-LAUNCH.json", launch)
    write(ROOT / "SOURCE4-PREEXEC.json", {
        "schema": "hepta.hia.fixed-transport-source4-preexec.v1", "status": "FROZEN_UNEXECUTED",
        "request": request_pin, "launch": launch_pin, "own_inputs": own,
        "runtime": runtime, "owner": owner, "source_record": source_record_pin,
        "expected_ids": expected,
        "source_full_bytes_observed": sum(row["size"] for row in source_pins),
        "source_files_observed": len(source_pins),
        "ast_only_controls": [raw_pin(ROOT / "control" / name) for name in (
            "source_controls.py", "launch_source4.py", "freeze_source4.py")],
    })
    print(json.dumps({"request": request_pin, "launch": launch_pin, "expected_ids": expected,
                      "source_files": len(source_pins), "source_bytes": sum(row["size"] for row in source_pins)}))


if __name__ == "__main__":
    main()

