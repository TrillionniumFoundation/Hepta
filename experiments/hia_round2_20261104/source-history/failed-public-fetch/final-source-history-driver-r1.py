"""Preserve and independently restore original Hepta commits after a public base.

Run only after the separately registered composition has reached a terminal state.
This is a delivery operation, not a compiler, benchmark, proof, or model run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import time


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def file_record(path):
    path = Path(path)
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": h.hexdigest()}


def save(path, value):
    raw = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    with Path(path).open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw)}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def exact_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def main():
    entered = time.monotonic_ns()
    entered_unix = time.time_ns()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan")
    parser.add_argument("plan_sha256")
    args = parser.parse_args()
    plan_path = Path(args.plan)
    plan_raw = plan_path.read_bytes()
    require(sha256(plan_raw) == args.plan_sha256, "source-history plan drift")
    plan = exact_json(plan_raw)
    require(plan["schema"] == "hepta.hia.final-source-history-plan.v1", "unexpected plan schema")
    actual_driver = file_record(__file__)
    require(actual_driver["path"] == plan["driver_path"] and
            actual_driver["sha256"] == plan["driver_sha256"], "source-history driver drift")
    root = Path(plan["source_root"])
    output = Path(plan["output"])
    require(root.is_absolute() and output.is_absolute() and not output.is_relative_to(root), "independent absolute output required")
    require(not output.exists(), "fresh source-history output required")
    output.mkdir()
    logs = output / "commands"
    logs.mkdir()
    expected = plan["source"]
    base = plan["public_prerequisite"]
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0",
               GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1", GIT_OPTIONAL_LOCKS="0",
               PYTHONDONTWRITEBYTECODE="1")
    commands = []
    result = {"schema": "hepta.hia.final-source-history.v1", "status": "failed", "passed": False,
              "source_expected": expected, "public_prerequisite": base,
              "public_repository": plan["public_repository"], "public_projection": plan["public_projection"],
              "original_full_qualification_passed": False,
              "scope": "Exact original source-history restoration after one public prerequisite; not experiment replay, proof acceptance, performance qualification, or production authorization.",
              "source_after": None, "source_unchanged": False, "exception": None,
              "started_unix_ns": entered_unix, "host_exclusive": False,
              "cost_scope": "Main-entry clock through terminal receipt preparation, including all nested delivery commands; interpreter startup/imports and the final RESULT write are outside this clock. Never add nested command walls again. Runtime supervision receipts are retained separately. This occurs after composition and before formal Agent inference.",
              "plan": {"path": str(plan_path), "bytes": len(plan_raw), "sha256": sha256(plan_raw)},
              "driver": actual_driver, "commands": commands}

    def run(name, argv, cwd=root, timeout=600, allowed=(0,)):
        number = len(commands) + 1
        prefix = logs / (f"{number:03d}-" + name)
        out_path, err_path = Path(str(prefix) + ".stdout"), Path(str(prefix) + ".stderr")
        before = time.monotonic_ns()
        row = {"name": name, "argv": [str(x) for x in argv], "cwd": str(cwd),
               "timeout_seconds": timeout, "allowed_returncodes": list(allowed),
               "started_unix_ns": time.time_ns(), "returncode": None, "timed_out": False,
               "launch_error": None}
        with out_path.open("xb") as stdout, err_path.open("xb") as stderr:
            try:
                proc = subprocess.Popen(row["argv"], cwd=cwd, env=env, stdout=stdout,
                                        stderr=stderr, start_new_session=True)
            except OSError as error:
                row["launch_error"] = {"type": type(error).__name__, "message": str(error)}
            else:
                try:
                    row["returncode"] = proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    row["timed_out"] = True
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    row["returncode"] = proc.wait(timeout=10)
                    row["killed_group_before_reap"] = True
        row["wall_ns"] = time.monotonic_ns() - before
        row["stdout"] = file_record(out_path)
        row["stderr"] = file_record(err_path)
        commands.append(row)
        save(Path(str(prefix) + ".json"), row)
        require(not row["timed_out"] and row["launch_error"] is None and row["returncode"] in allowed,
                "delivery command failed: " + name)
        return out_path.read_bytes(), row

    def source_state(label):
        values, _ = run(label + "-identity", ["git", "rev-parse", "HEAD", "HEAD^{tree}"], timeout=30)
        commit, tree = values.decode().splitlines()
        status, _ = run(label + "-status", ["git", "status", "--porcelain=v1", "--untracked-files=all"], timeout=30)
        return {"commit": commit, "tree": tree, "status": status.decode()}

    def check_store(repository):
        objects = repository / "objects"
        require(not (objects / "info/alternates").exists(), "independent restore has alternates")
        count = 0
        for path in objects.rglob("*"):
            require(not path.is_symlink(), "independent object store has a symlink")
            if path.is_file():
                require(path.stat().st_nlink == 1, "independent object store has a hard link")
                require(not path.name.endswith(".promisor"), "independent object store is partial")
                count += 1
        return {"ordinary_object_store_files": count, "alternates": False, "hard_links": False,
                "symlinks": False, "promisor_packs": False}

    try:
        required = []
        for wanted in plan["prerequisite_receipts"]:
            actual = file_record(wanted["path"])
            require(actual == wanted, "prerequisite receipt drift: " + wanted["path"])
            required.append(actual)
        result["prerequisite_receipts"] = required
        outer = exact_json(Path(plan["composition_outer_receipt"]).read_bytes())
        require(outer.get("returncode") is not None and outer.get("source_unchanged") is True,
                "composition is not terminal on unchanged source")
        result["composition_outcome_preserved"] = {key: outer.get(key) for key in
            ("returncode", "successful_process_and_source_identity", "composition_receipt_error", "wall_ns")}
        result["source_before"] = source_state("source-before")
        require(result["source_before"] == {**expected, "status": ""}, "source differs from frozen original")
        run("public-base-ancestor", ["git", "merge-base", "--is-ancestor", base, expected["commit"]], timeout=30)
        base_tree, _ = run("public-base-tree", ["git", "rev-parse", base + "^{tree}"], timeout=30)
        result["public_prerequisite_tree"] = base_tree.decode().strip()
        ancestry, _ = run("original-commit-history", ["git", "rev-list", "--reverse", "--topo-order", "--parents", base + ".." + expected["commit"]], timeout=30)
        result["original_commits_after_base"] = [line.split() for line in ancestry.decode().splitlines()]
        tree_raw, _ = run("original-tree", ["git", "ls-tree", "-rz", expected["commit"]], timeout=30)
        tracked_raw, _ = run("original-tracked-paths", ["git", "ls-files", "-z"], timeout=30)
        entries = []
        for raw_entry in tree_raw.split(b"\0"):
            if not raw_entry:
                continue
            header, name = raw_entry.split(b"\t", 1)
            mode, kind, identity = header.decode("ascii").split()
            entries.append({"path": os.fsdecode(name), "mode": mode, "kind": kind, "git_blob": identity})
        require(len(entries) == plan["expected_tracked_paths"], "full final tree inventory differs")
        require({os.fsdecode(x) for x in tracked_raw.split(b"\0") if x} == {x["path"] for x in entries},
                "tracked file inventory differs from original tree")
        for item in entries:
            path = root / item["path"]
            require(item["kind"] == "blob", "non-blob tracked entry requires a separate restoration profile")
            before = path.lstat()
            if item["mode"] == "120000":
                require(stat.S_ISLNK(before.st_mode), "tracked symlink materialization differs")
                data = os.fsencode(os.readlink(path))
                git_hash = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data)
                digest = hashlib.sha256(data)
                size = len(data)
            else:
                require(item["mode"] in ("100644", "100755") and stat.S_ISREG(before.st_mode),
                        "tracked ordinary file materialization differs")
                size = before.st_size
                git_hash = hashlib.sha1(b"blob " + str(size).encode() + b"\0")
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        git_hash.update(block)
                        digest.update(block)
            after = path.lstat()
            require((before.st_ino, before.st_size, before.st_mtime_ns) ==
                    (after.st_ino, after.st_size, after.st_mtime_ns), "tracked file changed while hashing")
            require(git_hash.hexdigest() == item["git_blob"], "materialized bytes differ from original Git blob")
            item.update(bytes=size, sha256=digest.hexdigest())
        result["tracked_inventory"] = save(output / "TRACKED_INVENTORY.json", entries)
        result["tracked_paths"] = len(entries)
        result["original_tree_record_sha256"] = sha256(tree_raw)
        bundle = output / "original-source.bundle"
        run("bundle-create", ["git", "bundle", "create", "--version=2", str(bundle), "HEAD", "^" + base])
        header = []
        with bundle.open("rb") as stream:
            while True:
                line = stream.readline()
                require(line, "missing bundle header terminator")
                if line == b"\n":
                    break
                header.append(line.decode("utf-8").rstrip("\n"))
        prerequisites = [line[1:].split(" ", 1)[0] for line in header if line.startswith("-")]
        require(prerequisites == [base], "bundle must have exactly the public prerequisite")
        heads, _ = run("bundle-heads", ["git", "bundle", "list-heads", str(bundle)], timeout=30)
        require(heads.decode().splitlines() == [expected["commit"] + " HEAD"], "bundle original HEAD differs")
        result["bundle_header"] = header
        result["bundle"] = file_record(bundle)
        restore = output / "independent-restore.git"
        run("restore-init", ["git", "init", "--bare", "--initial-branch=public-prerequisite", str(restore)], timeout=30)
        # The measured local source repository is shallow. Obtain the public base
        # directly into this new repository without changing the measured source.
        seed_url = plan["prerequisite_seed_url"]
        require(seed_url == "https://github.com/TrillionniumFoundation/Hepta.git", "unexpected public prerequisite repository")
        run("restore-public-prerequisite", ["git", "-C", str(restore), "fetch", "--no-tags", seed_url,
                                             base + ":refs/heads/public-prerequisite"], timeout=900)
        shallow, _ = run("restore-public-not-shallow", ["git", "-C", str(restore), "rev-parse", "--is-shallow-repository"], timeout=30)
        require(shallow.strip() == b"false", "public prerequisite closure must not be shallow")
        seed, _ = run("restore-public-identity", ["git", "-C", str(restore), "rev-parse",
                    "refs/heads/public-prerequisite", "refs/heads/public-prerequisite^{tree}"], timeout=30)
        require(seed.decode().splitlines() == [base, result["public_prerequisite_tree"]], "public seed identity differs")
        result["seed_object_store"] = check_store(restore)
        reachable, _ = run("restore-public-reachable-objects", ["git", "-C", str(restore), "rev-list", "--objects", base])
        stored, _ = run("restore-public-stored-objects", ["git", "-C", str(restore), "cat-file", "--batch-all-objects", "--batch-check=%(objectname)"])
        reachable_ids = {line.split(b" ", 1)[0] for line in reachable.splitlines()}
        stored_ids = set(stored.splitlines())
        require(reachable_ids == stored_ids, "seed contains objects outside the public prerequisite closure")
        result["seed_exact_public_closure"] = {"objects": len(reachable_ids), "no_other_objects": True,
            "object_id_inventory_sha256": sha256(b"\n".join(sorted(reachable_ids)) + b"\n")}
        _, absent = run("restore-original-head-absent", ["git", "-C", str(restore), "cat-file", "-e",
                         expected["commit"] + "^{commit}"], timeout=30, allowed=(1, 128))
        result["original_head_absent_before_import"] = absent["returncode"] != 0
        run("restore-bundle-verify", ["git", "-C", str(restore), "bundle", "verify", str(bundle)])
        run("restore-bundle-import", ["git", "-C", str(restore), "fetch", "--no-tags", str(bundle),
                                       "HEAD:refs/heads/restored-source"])
        run("restore-head-select", ["git", "-C", str(restore), "symbolic-ref", "HEAD", "refs/heads/restored-source"], timeout=30)
        restored, _ = run("restore-original-identity", ["git", "-C", str(restore), "rev-parse", "HEAD", "HEAD^{tree}"], timeout=30)
        require(restored.decode().splitlines() == [expected["commit"], expected["tree"]], "restored original identity differs")
        restored_tree, _ = run("restore-tree", ["git", "-C", str(restore), "ls-tree", "-rz", "HEAD"], timeout=30)
        require(restored_tree == tree_raw, "restored complete tree differs")
        run("restore-fsck", ["git", "-C", str(restore), "fsck", "--full", "--strict"], timeout=900)
        result["restored_object_store"] = check_store(restore)
        # Stream every original tracked blob from the independent object store.
        # The bundle retains these bytes; this diagnostic records their full hashes.
        ids_path = output / "RESTORE_BLOB_REQUESTS.txt"
        with ids_path.open("xb") as stream:
            stream.write(b"".join((item["git_blob"] + "\n").encode() for item in entries))
        before = time.monotonic_ns()
        stderr_path = output / "restore-blob-stream.stderr"
        actual_hashes = []
        with ids_path.open("rb") as requests, stderr_path.open("xb") as errors:
            proc = subprocess.Popen(["git", "-C", str(restore), "cat-file", "--batch"],
                                    stdin=requests, stdout=subprocess.PIPE, stderr=errors, env=env,
                                    start_new_session=True)
            try:
                require(proc.stdout is not None, "missing blob stream")
                for wanted in entries:
                    fields = proc.stdout.readline().decode("ascii").strip().split()
                    require(fields == [wanted["git_blob"], "blob", str(wanted["bytes"])], "restored blob header differs")
                    remaining = wanted["bytes"]
                    h = hashlib.sha256()
                    while remaining:
                        chunk = proc.stdout.read(min(remaining, 1024 * 1024))
                        require(bool(chunk), "truncated restored blob")
                        h.update(chunk)
                        remaining -= len(chunk)
                    require(proc.stdout.read(1) == b"\n", "restored blob frame differs")
                    require(h.hexdigest() == wanted["sha256"], "restored tracked blob bytes differ")
                    actual_hashes.append({"path": wanted["path"], "git_blob": wanted["git_blob"],
                                          "bytes": wanted["bytes"], "sha256": h.hexdigest()})
                require(proc.stdout.read(1) == b"", "unexpected restored blob frames")
                require(proc.wait(timeout=30) == 0, "restored blob stream failed")
            finally:
                if proc.poll() is None:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.wait(timeout=10)
        result["restore_blob_stream"] = {"argv": ["git", "-C", str(restore), "cat-file", "--batch"],
            "request": file_record(ids_path), "stderr": file_record(stderr_path), "returncode": proc.returncode,
            "wall_ns": time.monotonic_ns() - before, "full_tracked_blob_count": len(actual_hashes),
            "inventory": save(output / "RESTORED_BLOBS.json", actual_hashes),
            "raw_stdout_retention": "Blob data are retained by original-source.bundle plus the public prerequisite, and were streamed for independent SHA256 comparison."}
        require(file_record(bundle) == result["bundle"], "bundle drifted during restoration")
        parts = []
        with bundle.open("rb") as stream:
            while True:
                raw = stream.read(768 * 1024)
                if not raw:
                    break
                path = output / ("original-source.bundle.part" + f"{len(parts)+1:04d}")
                with path.open("xb") as target:
                    target.write(raw)
                parts.append(file_record(path))
        h = hashlib.sha256()
        for part in parts:
            with Path(part["path"]).open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    h.update(block)
        require(h.hexdigest() == result["bundle"]["sha256"], "bundle split restoration differs")
        result["bundle_parts"] = parts
        result["source_after"] = source_state("source-after")
        result["source_unchanged"] = result["source_after"] == result["source_before"]
        require(result["source_unchanged"], "source changed during delivery")
        result["status"] = "completed"
        result["passed"] = True
    except Exception as error:
        result["exception"] = {"type": type(error).__name__, "message": str(error)}
        if result["source_after"] is None:
            try:
                result["source_after"] = source_state("source-after-failure")
                result["source_unchanged"] = result["source_after"] == result.get("source_before")
            except Exception as later:
                result["source_after_error"] = {"type": type(later).__name__, "message": str(later)}
    result["finished_unix_ns"] = time.time_ns()
    result["wall_ns"] = time.monotonic_ns() - entered
    save(output / "RESULT.json", result)
    print(json.dumps({key: result.get(key) for key in ("status", "passed", "source_expected", "public_prerequisite", "bundle", "tracked_paths", "source_unchanged", "exception", "wall_ns")}, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
