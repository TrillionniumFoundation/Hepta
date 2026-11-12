"""Original-180/3 outer owner for the bounded-read finite development driver.

This script is a static, unexecuted control candidate. It provides no workflow,
remote job key or authorization to launch itself. Exact external input pins and
a fresh source/evidence location must be reviewed before any actual invocation.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
import stat
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).absolute().parent))
from source_common import (_checked_parent, _create_directory, create, identity,
                           pin, read, require, wire)
from native_support import (CANDIDATE, CANDIDATE_TREE, COMPILER_BYTES, COMPILER_SHA,
                            OWNER_SHA, load_fixed_module, owned_step)
from native_driver import controls

def evidence_inventory(root):
    """Read only after the exact outer ECHILD; preserve special nodes as metadata.

    These 4096/128MiB bounds constrain evidence observation only. They do not
    change any product file input limit, test population, or timing budget.
    """
    if not os.path.lexists(root):
        return {"missing": True, "members": [], "regular_bytes": 0}
    with _checked_parent(root / ".inventory-spine-probe"):
        pass
    rows, total = [], 0
    def append(path, info):
        nonlocal total
        relative = path.relative_to(root).as_posix()
        row = {"path": relative, "identity": list(identity(info))}
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
            require(total <= 128 << 20, "evidence regular-byte budget exceeded")
            raw, actual = read(path, 128 << 20)
            require(actual["identity"] == list(identity(info)), "evidence changed since typed observation")
            row.update(kind="regular", **pin(raw))
        elif stat.S_ISDIR(info.st_mode):
            row["kind"] = "directory"
        elif stat.S_ISLNK(info.st_mode):
            row.update(kind="symlink", target=os.readlink(path))
            require(identity(path.lstat()) == identity(info), "evidence symlink changed")
        else:
            row.update(kind="special", no_open_or_follow_performed=True)
        rows.append(row)
        require(len(rows) <= 4096, "evidence member budget exceeded")
    def walk_error(error):
        raise error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        directory = Path(directory)
        append(directory, directory.lstat())
        for name in list(dirs):
            path = directory / name
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode):
                dirs.remove(name)
                append(path, info)
        for name in files:
            path = directory / name
            append(path, path.lstat())
    for row in rows:
        path = root if row["path"] == "." else root / row["path"]
        require(list(identity(path.lstat())) == row["identity"], "evidence member changed during inventory")
    return {"schema": "hepta.hia.bounded-read-development-typed-evidence.v1",
            "members": rows, "regular_bytes": total, "all_reads_after_outer_ECHILD": True,
            "symlinks_and_specials_not_followed": True}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--control-manifest", type=Path, required=True)
    parser.add_argument("--control-manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, output = args.source_root, args.output
    require(source.is_absolute() and output.is_absolute() and ".." not in source.parts
            and ".." not in output.parts and source != output and source not in output.parents,
            "separate absolute candidate and outer evidence roots required")
    with _checked_parent(output):
        pass
    capacity = os.statvfs(output.parent)
    require(capacity.f_bavail * capacity.f_frsize >= 8 << 30 and capacity.f_favail >= 100000,
            "unchanged private storage/inode reserve unavailable")
    _create_directory(output)
    result = {"schema": "hepta.hia.bounded-read-native-development-outer.v1",
        "status": "HOLD", "candidate_commit": CANDIDATE, "candidate_tree": CANDIDATE_TREE,
        "processes": [], "errors": [], "qualification_seconds": 180, "cleanup_seconds": 3,
        "finite_component_cases": 55, "original_methods": 8, "original_CLI_children": 7,
        "cold_qualification": False, "installed_qualification": False,
        "whole_native_delivery_qualified": False, "all_input_equivalence_proved": False,
        "capacity_before": {"free_bytes": capacity.f_bavail * capacity.f_frsize,
                            "free_inodes": capacity.f_favail}}
    before = manifest_raw = manifest_pin = compiler_pin = None
    closed = False
    try:
        require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode
                and sys.version_info[:3] == (3, 14, 4), "fixed actual outer interpreter differs")
        require(not any(name.startswith(("HEPTA_HIA_", "LD_"))
                    or name in ("PYTHONPATH", "PYTHONHOME") for name in os.environ),
                "ambient selector or loader override refused")
        value, manifest_raw, manifest_pin, before = controls(
            args.control_manifest, args.control_manifest_sha256)
        result["control_manifest"] = manifest_pin
        result["control_before"] = before
        compiler_raw, compiler_pin = read(args.compiler, COMPILER_BYTES)
        require(len(compiler_raw) == COMPILER_BYTES and compiler_pin["sha256"] == COMPILER_SHA,
                "fixed B3 development input differs")
        result["compiler_before"] = compiler_pin
        root = Path(__file__).absolute().parent
        owner, result["owner_module"] = load_fixed_module(
            "_bounded_read_outer_process_owner", root / "process_owner_impl.py", OWNER_SHA)
        python = str(Path(sys.executable).absolute())
        environment = {"PATH": os.environ["PATH"], "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                       "PYTHONDONTWRITEBYTECODE": "1"}
        command = [python, "-I", "-S", "-B", str(root / "native_driver.py"),
            "--source-root", str(source), "--source-manifest", str(root / "source-manifest.json"),
            "--control-manifest", str(args.control_manifest),
            "--control-manifest-sha256", args.control_manifest_sha256,
            "--compiler", str(args.compiler), "--output", str(output / "run")]
        owned_step(owner, output, result, "outer", command, source, environment, 180)
        closed = True
        raw, record = read(output / "run/report.json", 8 << 20)
        driver = json.loads(raw)
        result["driver_original"] = record
        require(driver["schema"] == "hepta.hia.bounded-read-native-development.v1"
                and driver["status"] == "BOUNDED_READ_DEVELOPMENT_PASS_PENDING_OUTER_GUARDIAN"
                and driver["candidate_commit"] == CANDIDATE
                and driver["candidate_tree"] == CANDIDATE_TREE
                and driver["outer_qualification_seconds_required"] == 180
                and driver["outer_cleanup_seconds_required"] == 3
                and driver["all_started_inner_owners_closed"] is True
                and driver["source_stable_except_new_resource"] is True
                and driver["control_before"] == driver["control_after"] == before
                and driver["control_manifest"] == manifest_pin
                and driver["compiler_before"] == driver["compiler_after"] == compiler_pin
                and driver["bundle_before"] == driver["bundle_after"]
                and driver["errors"] == [] and driver["not_completed_groups"] == []
                and len(driver["groups"]) == 5 and len(driver["processes"]) == 6
                and all(row["status"] == "OWNED_STEP_PASS" for row in driver["processes"])
                and all(state == "ACTUAL_COMPLETE_PASS" for state in driver["group_execution"].values()),
                "complete driver/inner-owner/outer-owner conjunction failed")
        require(driver["cold_qualification"] is False and driver["installed_qualification"] is False
                and driver["whole_native_delivery_qualified"] is False,
                "finite development scope was broadened")
        result["status"] = "BOUNDED_READ_FINITE_DEVELOPMENT_PASS_NOT_QUALIFICATION"
    except BaseException as error:
        result["status"] = "HOLD"
        result["errors"].append({"type": type(error).__name__, "text": str(error),
                                 "traceback": traceback.format_exc()})
    finally:
        if result["processes"]:
            closed = all(row.get("cleanup_closed_before_original_read") is True
                         for row in result["processes"])
        else:
            closed = True
        result["outer_cleanup_closed_before_output_read"] = closed
        if closed:
            try:
                if before is not None:
                    _, current_raw, current_pin, after = controls(
                        args.control_manifest, args.control_manifest_sha256)
                    require(current_raw == manifest_raw and current_pin == manifest_pin
                            and after == before, "outer fixed controls changed")
                    result["control_after"] = after
                if compiler_pin is not None:
                    result["compiler_after"] = read(args.compiler, COMPILER_BYTES)[1]
                    require(result["compiler_after"] == compiler_pin, "outer B3 input changed")
                # These are fixed, not dynamically chosen from a successful
                # report. Failed/unstarted files are individually explicit.
                result["terminal_originals"] = []
                fixed = ["run/report.json", "run/build/report.json", "run/build/bounded-read.hiaasm",
                    "run/build/bounded-read.hia.json", "run/build/bounded-read.receipt.json",
                    "run/build/bounded-read.stdout.log", "run/build/bounded-read.stderr.log",
                    "run/build/manifest.json", "run/reject/report.json", "run/lifetime/report.json",
                    "run/permission/report.json", "run/filesystem/report.json",
                    "run/original-eight/report.json", "run/original-eight/unittest.log"]
                for name in fixed:
                    path = output / name
                    try:
                        _, record = read(path, 8 << 20)
                        result["terminal_originals"].append({"name": name, "record": record})
                    except FileNotFoundError:
                        result["terminal_originals"].append({"name": name, "missing": True})
                        if result["status"] == "BOUNDED_READ_FINITE_DEVELOPMENT_PASS_NOT_QUALIFICATION":
                            result["status"] = "HOLD"
                            result["errors"].append({"phase": "terminal_custody", "name": name,
                                                      "type": "RequiredOriginalMissing"})
                    except BaseException as error:
                        result["status"] = "HOLD"
                        result["errors"].append({"phase": "terminal_custody", "name": name,
                            "type": type(error).__name__, "traceback": traceback.format_exc()})
                inventory = evidence_inventory(output / "run")
                result["typed_evidence_inventory"] = create(output / "EVIDENCE-INVENTORY.json", wire(inventory))
            except BaseException as error:
                result["status"] = "HOLD"
                result["errors"].append({"phase": "outer_final_readback",
                    "type": type(error).__name__, "traceback": traceback.format_exc()})
        else:
            result["status"] = "HOLD"
            result["custody_deferred_until_confirmed_ECHILD"] = True
        create(output / "ACCEPTANCE.json", wire(result))
    print(json.dumps({"status": result["status"], "candidate_commit": CANDIDATE,
                      "cold_qualification": False}), flush=True)
    return 0 if result["status"] == "BOUNDED_READ_FINITE_DEVELOPMENT_PASS_NOT_QUALIFICATION" else 1

if __name__ == "__main__":
    raise SystemExit(main())
