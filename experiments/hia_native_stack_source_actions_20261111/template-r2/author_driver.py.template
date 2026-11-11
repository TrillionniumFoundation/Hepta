"""Separate CI setup from one 180-second full-source reproduction operation."""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import platform
import stat
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from author_common import (BASE_COMMIT, BASE_TREE, GOOD_AUTHOR_STATUS, OWNER_SHA256,
    POLICY_SHA256, atomic_report, base_entries, below, blob, check_unchanged_outside,
    create, digest, git, load_policy, natural_owner,
    read_regular, require, save_new, wire)

CONTROL = Path(__file__).resolve().parent

def context():
    selected = ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_EVENT_NAME", "GITHUB_REF",
                "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA")
    value = {name: os.environ.get(name) for name in selected}
    require(value["GITHUB_REPOSITORY"] == "TrillionniumFoundation/Hepta"
            and value["GITHUB_EVENT_NAME"] == "create"
            and value["GITHUB_REF"] == "refs/heads/codex/hia-native-stack-source-r1-run-20261111-e26e"
            and value["GITHUB_RUN_ATTEMPT"] == "1"
            and str(value["GITHUB_RUN_ID"]).isdigit(), "unexpected one-shot event")
    raw, _ = read_regular(Path(os.environ["GITHUB_EVENT_PATH"]))
    event = json.loads(raw)
    require(event.get("ref_type") == "branch"
            and event.get("ref") == "codex/hia-native-stack-source-r1-run-20261111-e26e",
            "event payload differs")
    require(value["GITHUB_WORKFLOW_SHA"] == value["GITHUB_SHA"], "workflow/event commit differ")
    value["event_payload_sha256"] = digest(raw)
    return value

def control_state(expected_commit):
    checkout = CONTROL
    while checkout.name != "control" and checkout != checkout.parent:
        checkout = checkout.parent
    require(checkout.name == "control", "unexpected control checkout location")
    require(git(checkout, "rev-parse", "HEAD").decode().strip() == expected_commit,
            "control checkout HEAD differs")
    raw, _ = read_regular(CONTROL / "CONTROL-MANIFEST.json")
    manifest = json.loads(raw)
    require(manifest["schema"] == "hia.native-stack-actions.control-manifest.v1",
            "control manifest schema differs")
    require(manifest["policy_sha256"] == POLICY_SHA256, "manifest policy differs")
    paths = set()
    rows = []
    for item in manifest["files"]:
        require(item["path"] not in paths, "duplicate control file")
        paths.add(item["path"])
        contents, info = read_regular(CONTROL / item["path"])
        require(len(contents) == item["bytes"] and digest(contents) == item["sha256"]
                and blob(contents) == item["git_blob"], "control file differs: " + item["path"])
        rows.append({**item, "actual_posix_mode": stat.S_IMODE(info.st_mode)})
    actual = set()
    for directory, dirs, files in os.walk(CONTROL, followlinks=False):
        for name in dirs:
            require(not (Path(directory) / name).is_symlink(), "control directory symlink")
        for name in files:
            actual.add((Path(directory) / name).relative_to(CONTROL).as_posix())
    require(actual == paths | {"CONTROL-MANIFEST.json"}, "extra/missing control file")
    require(not git(checkout, "status", "--porcelain", "--untracked-files=no"),
            "tracked control checkout was changed")
    return {"commit": expected_commit, "manifest_sha256": digest(raw), "files": rows}

def seal_bundle(root):
    rows = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            require(not (Path(directory) / name).is_symlink(), "evidence directory symlink")
        for name in files:
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            require(relative != "AUTHOR-BUNDLE.json", "bundle was already sealed")
            raw, info = read_regular(path)
            rows.append({"path": relative, "bytes": len(raw), "sha256": digest(raw),
                         "git_blob": blob(raw), "posix_mode": stat.S_IMODE(info.st_mode),
                         "kind": "regular"})
    rows.sort(key=lambda r: r["path"])
    save_new(root / "AUTHOR-BUNDLE.json", {
        "schema": "hia.native-stack-actions.original-bundle.v1", "files": rows,
        "file_count": len(rows), "total_bytes": sum(r["bytes"] for r in rows),
        "native_compilation_executed": False, "product_tests_executed": False,
    })

def capture_actual_sources(source, root, base, candidate_paths):
    """Retain changed regular bytes and typed special-member metadata before admission."""
    before = {item["path"]: item for item in base}
    members, regular_rows, changed, refusals, errors = [], [], [], [], []
    observed_names = set()

    def observe(path):
        name = path.relative_to(source).as_posix()
        observed_names.add(name)
        record = {"path": name}
        members.append(record)
        try:
            info = path.lstat()
            record.update(posix_mode=stat.S_IMODE(info.st_mode), size=info.st_size,
                          device=info.st_dev, inode=info.st_ino, links=info.st_nlink,
                          mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)
            if stat.S_ISREG(info.st_mode):
                record["kind"] = "regular"
                raw, info = read_regular(path, single_link=False)
                item = {"path": name, "mode": "100755" if info.st_mode & 0o111 else "100644",
                        "git_blob": blob(raw), "bytes": len(raw), "sha256": digest(raw),
                        "posix_mode": stat.S_IMODE(info.st_mode)}
                regular_rows.append(item)
                record.update(item)
                old = before.get(name)
                if (old is None or any(old[key] != item[key] for key in ("mode", "git_blob"))
                        or info.st_nlink != 1):
                    artifact_path = "changed-source-originals/" + name
                    create(below(root, artifact_path), raw)
                    changed.append({**item, "artifact_path": artifact_path})
                if info.st_nlink != 1 or info.st_mode & 0o111:
                    refusals.append({"path": name, "reason": "source regular file mode/link admission"})
            elif stat.S_ISLNK(info.st_mode):
                record.update(kind="symlink", target=os.readlink(path))
                refusals.append({"path": name, "reason": "source symlink; target not followed"})
            elif stat.S_ISDIR(info.st_mode):
                record["kind"] = "directory"
            else:
                record["kind"] = ("fifo" if stat.S_ISFIFO(info.st_mode) else
                    "socket" if stat.S_ISSOCK(info.st_mode) else
                    "block-device" if stat.S_ISBLK(info.st_mode) else
                    "character-device" if stat.S_ISCHR(info.st_mode) else "unknown")
                record["rdev"] = info.st_rdev
                refusals.append({"path": name, "reason": "special source member; not opened"})
        except BaseException:
            record["capture_error"] = traceback.format_exc()
            errors.append({"path": name, "exception": record["capture_error"]})

    def walk_error(error):
        errors.append({"path": str(error.filename), "exception": repr(error)})

    for directory, dirs, files in os.walk(source, followlinks=False, onerror=walk_error):
        here = Path(directory)
        if here == source and ".git" in dirs:
            dirs.remove(".git")
        for name in sorted(dirs):
            path = here / name
            observe(path)
            # No link, device or unreadable directory can lead traversal elsewhere.
            try:
                if not stat.S_ISDIR(path.lstat().st_mode):
                    dirs.remove(name)
            except OSError:
                dirs.remove(name)
        for name in sorted(files):
            if here == source and name == ".git":
                refusals.append({"path": ".git", "reason": "unexpected Git worktree indirection"})
            observe(here / name)
    regular_rows.sort(key=lambda item: item["path"])
    changed.sort(key=lambda item: item["path"])
    members.sort(key=lambda item: item["path"])
    capture = {
        "schema": "hia.native-stack-actions.typed-source-capture.v1",
        "members": members, "regular_source_leaves": len(regular_rows),
        "changed_regular_files": len(changed), "capture_errors": errors,
        "refused_members": refusals, "capture_complete": not errors,
        "special_members_opened": False, "symlink_targets_followed": False,
    }
    save_new(root / "SOURCE-CAPTURE-INVENTORY.json", capture)
    save_new(root / "captured-source-leaves.json", regular_rows)
    save_new(root / "ALL-SOURCE-CHANGES.json", {
        "schema": "hia.native-stack-actions.all-actual-source-changes.v1",
        "files": changed, "deleted_paths": sorted(set(before) - observed_names),
        "candidate_allowlist": candidate_paths, "capture_errors": errors,
        "refused_members": refusals, "capture_complete": not errors,
        "unapproved_changes_are_not_admitted": True,
        "special_member_metadata_path": "SOURCE-CAPTURE-INVENTORY.json",
    })
    return regular_rows, capture

def prepare(args):
    root = Path(args.work_root)
    root.mkdir(mode=0o700)
    setup = {"schema": "hia.native-stack-actions.setup.v1", "status": "HOLD",
             "setup_outside_authoring_budget": True, "authoring_started": False,
             "native_compilation_executed": False, "product_tests_executed": False}
    started = time.monotonic()
    try:
        source = Path(args.source).resolve(strict=True)
        workspace = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
        require(source == workspace / "source", "unexpected source checkout path")
        require(root.absolute() == Path(os.environ["RUNNER_TEMP"]) / "hia-native-stack-source-r1",
                "unexpected private evidence root")
        require(tuple(sys.version_info[:3]) == (3, 14, 4), "Python version differs")
        policy = load_policy(CONTROL)
        setup["context"] = context()
        setup["control"] = control_state(args.control_commit)
        entries = base_entries(source)
        require(git(source, "write-tree").decode().strip() == BASE_TREE,
                "base checkout index differs")
        require(not git(source, "status", "--porcelain", "--untracked-files=all"),
                "base checkout is not clean")
        for item in policy["base_workflows"]:
            raw, _ = read_regular(source / item["path"])
            require(blob(raw) == item["git_blob"] and digest(raw) == item["sha256"],
                    "original workflow bytes differ")
        owner_raw, _ = read_regular(source / policy["owner_path"])
        require(digest(owner_raw) == OWNER_SHA256, "original owner differs")
        binary = Path(sys.executable).resolve(strict=True)
        binary_raw, _ = read_regular(binary, single_link=False)
        setup["runtime"] = {"executable": sys.executable, "resolved_binary": str(binary),
                            "binary_sha256": digest(binary_raw), "binary_bytes": len(binary_raw),
                            "python": sys.version, "platform": platform.platform()}
        fs = os.statvfs(root)
        setup["storage_before"] = {"available_bytes": fs.f_bavail * fs.f_frsize,
                                   "available_inodes": fs.f_favail, "device": root.stat().st_dev}
        require(fs.f_bavail * fs.f_frsize >= 2 * (1 << 30), "authoring storage below original request")
        setup["base"] = {"commit": BASE_COMMIT, "tree": BASE_TREE, "leaves": len(entries)}
        for name in ("commands", "candidate"):
            (root / name).mkdir(mode=0o700)
        for source_name, destination in (("policy.json", "policy.original.json"),
             ("INPUT-STATUS.json", "input-status.original.json"),
             ("CONTROL-MANIFEST.json", "control-manifest.original.json")):
            raw, _ = read_regular(CONTROL / source_name)
            create(root / destination, raw)
        environment = {
            "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
        }
        request = {
            "schema": "hia.native-stack-actions.owned-request.v1",
            "source": str(source), "root": str(root), "control_commit": args.control_commit,
            "control_manifest_sha256": setup["control"]["manifest_sha256"],
            "policy_sha256": POLICY_SHA256, "owner_sha256": OWNER_SHA256,
            "command": [sys.executable, "-I", "-S", "-B", str(CONTROL / "source_worker.py"),
                        str(root), str(source)], "env": environment,
            "qualification_seconds": 180, "cleanup_seconds": 3,
            "context": setup["context"], "runtime": setup["runtime"],
        }
        save_new(root / "request.json", request)
        setup["request_sha256"] = digest((root / "request.json").read_bytes())
        setup["status"] = "PREPARED_NOT_EXECUTED"
    except BaseException:
        setup["exception"] = traceback.format_exc()
    finally:
        setup["seconds"] = time.monotonic() - started
        atomic_report(root / "SETUP.json", setup)
        if setup["status"] != "PREPARED_NOT_EXECUTED":
            seal_bundle(root)
        print(json.dumps({k: setup.get(k) for k in ("schema", "status", "seconds", "exception")},
                         sort_keys=True), flush=True)
    return 0 if setup["status"] == "PREPARED_NOT_EXECUTED" else 1

def run(args):
    root = Path(args.work_root).resolve(strict=True)
    request_raw, _ = read_regular(root / "request.json")
    setup_raw, _ = read_regular(root / "SETUP.json")
    request, setup = json.loads(request_raw), json.loads(setup_raw)
    report = {
        "schema": "hia.native-stack-actions.owned-authoring.v1", "status": "HOLD",
        "scope": "ISOLATED_SOURCE_AUTHORING_ONLY", "request_sha256": digest(request_raw),
        "setup_sha256": digest(setup_raw), "native_compilation_executed": False,
        "product_tests_executed": False, "matching_current_cold": False, "whole_native_delivery": False,
    }
    started = time.monotonic()
    life = None
    try:
        policy = load_policy(CONTROL)
        require(setup["status"] == "PREPARED_NOT_EXECUTED"
                and setup["request_sha256"] == digest(request_raw), "setup/request binding differs")
        require(context() == request["context"], "event changed between setup and authoring")
        require(args.control_commit == request["control_commit"], "control commit changed")
        before = control_state(args.control_commit)
        require(before["manifest_sha256"] == request["control_manifest_sha256"], "control changed")
        report["control_before"] = before
        source = Path(request["source"]).resolve(strict=True)
        require(source == Path(args.source).resolve(strict=True), "source path changed")
        require(request["qualification_seconds"] == 180 and request["cleanup_seconds"] == 3,
                "fixed owner budgets differ")
        owner_path = source / policy["owner_path"]
        owner_raw, _ = read_regular(owner_path)
        require(digest(owner_raw) == OWNER_SHA256, "original owner bytes differ")
        spec = importlib.util.spec_from_file_location("_unchanged_hia_process_owner", owner_path)
        owner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owner)
        life = owner.run_owned(request["command"], cwd=source, env=request["env"],
            stdout_path=root / "child.stdout", stderr_path=root / "child.stderr",
            receipt_path=root / "lifecycle.json", qualification_seconds=180, cleanup_seconds=3)
        report["lifecycle"] = life
        report["natural_owner_success"] = natural_owner(life)
        report["owner_source_preserved"] = read_regular(owner_path)[0] == owner_raw
        report["control_after"] = control_state(args.control_commit)
        report["control_preserved"] = report["control_after"] == before
        worker = None
        try:
            worker_raw, _ = read_regular(root / "worker-report.json")
            worker = json.loads(worker_raw)
            require(type(worker) is dict, "worker report is not an object")
            report["worker_report_sha256"] = digest(worker_raw)
            report["worker_status"] = worker.get("status")
        except BaseException:
            # A timed-out worker may never finish its report. Once the
            # original owner has reaped all children, retain actual source
            # and raw logs independently of that missing report; keep HOLD.
            worker = None
            report["worker_report_error"] = traceback.format_exc()
            report["worker_status"] = None
        cleanup = life.get("cleanup", {})
        require(cleanup.get("complete") is True and cleanup.get("observed_echild") is True
                and cleanup.get("remaining_direct_children") == [], "source capture requires closed ownership")
        base = base_entries(source)
        after, captured = capture_actual_sources(source, root, base, policy["candidate_paths"])
        report["captured_source_leaf_count"] = len(after)
        report["all_actual_source_changes_captured"] = captured["capture_complete"]
        report["source_capture_refusals"] = captured["refused_members"]
        report["source_capture_errors"] = captured["capture_errors"]
        require(captured["capture_complete"] and not captured["refused_members"],
                "actual source capture is incomplete or contains refused member types/modes")
        check_unchanged_outside(base, after, set(policy["candidate_paths"]))
        rows = {item["path"]: item for item in after}
        exported = []
        for name in policy["candidate_paths"]:
            if name not in rows:
                continue
            raw, _ = read_regular(source / name)
            record = rows[name]
            require(digest(raw) == record["sha256"] and blob(raw) == record["git_blob"],
                    "source changed during capture")
            destination = below(root / "candidate", name)
            create(destination, raw)
            exported.append({**record, "artifact_path": "candidate/" + name})
        export = {"schema": "hia.native-stack-actions.actual-candidate-export.v1",
                  "base_commit": BASE_COMMIT, "base_tree": BASE_TREE,
                  "files": exported, "allowed_paths": policy["candidate_paths"],
                  "source_snapshot_sha256": digest((root / "captured-source-leaves.json").read_bytes()),
                  "actual_head": git(source, "rev-parse", "HEAD").decode().strip(),
                  "actual_index_tree": git(source, "write-tree").decode().strip(),
                  "not_claimed_checked_out_canonical_candidate_commit": True}
        save_new(root / "CANDIDATE-EXPORT.json", export)
        report["candidate_export_sha256"] = digest((root / "CANDIDATE-EXPORT.json").read_bytes())
        if worker is not None and worker.get("status") == GOOD_AUTHOR_STATUS:
            expected_raw, _ = read_regular(root / "candidate-source-leaves.json")
            require(json.loads(expected_raw) == after, "post-owner source differs from worker source")
            require(len(after) == policy["candidate_source_leaves"] and len(exported) == 2
                    and worker["candidate_index_tree"] == export["actual_index_tree"],
                    "complete candidate closure differs")
        okay = (report["natural_owner_success"] and report["owner_source_preserved"]
                and report["control_preserved"] and worker is not None
                and worker.get("status") == GOOD_AUTHOR_STATUS
                and worker.get("frozen_inputs_preserved") is True)
        report["status"] = GOOD_AUTHOR_STATUS if okay else "HOLD"
    except BaseException:
        report["exception"] = traceback.format_exc()
    finally:
        report["seconds"] = time.monotonic() - started
        atomic_report(root / "AUTHOR-CONTROL.json", report)
        seal_bundle(root)
        print(json.dumps({k: report.get(k) for k in ("schema", "status", "scope",
            "natural_owner_success", "worker_status", "seconds", "exception")}, sort_keys=True), flush=True)
    return 0 if report["status"] == GOOD_AUTHOR_STATUS else 1

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "run"))
    parser.add_argument("--work-root", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--control-commit", required=True)
    args = parser.parse_args()
    return prepare(args) if args.operation == "prepare" else run(args)

if __name__ == "__main__":
    raise SystemExit(main())
