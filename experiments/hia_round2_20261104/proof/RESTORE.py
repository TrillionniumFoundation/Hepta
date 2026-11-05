"""Create and restore a byte-exact archive of explicitly listed proof evidence.

Delivery only. This never executes archived code or reruns proofs or tests.
Run build only in the parent-assigned compression window. Existing output is
never reused, and every failure retains all already-created files.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import traceback


def require(ok, message):
    if not ok:
        raise ValueError(message)


def exact_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate JSON key")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def stamp(st):
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns,
            st.st_nlink, st.st_mode)


def regular(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, "nonordinary input: " + str(path))
    require(not stat.S_IMODE(st.st_mode) & ~0o777, "special permission bits")
    return st


def hashed(path):
    before = regular(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    h = hashlib.sha256()
    size = 0
    try:
        require(stamp(os.fstat(fd)) == stamp(before), "input identity changed")
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            h.update(block)
            size += len(block)
        require(stamp(os.fstat(fd)) == stamp(before) == stamp(path.lstat()), "input changed while hashing")
    finally:
        os.close(fd)
    require(size == before.st_size, "input size changed")
    return {"bytes": size, "sha256": h.hexdigest()}, before


def write(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": str(path), "bytes": len(raw), "sha256": digest(raw)}


def relative(name):
    p = PurePosixPath(name)
    require(type(name) is str and str(p) == name and not p.is_absolute(), "noncanonical relative path")
    require(name not in ("", ".") and all(x not in ("", ".", "..") for x in p.parts), "unsafe member path")
    return p


def collect(base, roots):
    require(roots == sorted(set(roots)), "roots must be sorted and unique")
    all_files, all_dirs, states = {}, {}, {}
    def visit(path, rel):
        s = path.lstat()
        if stat.S_ISDIR(s.st_mode):
            require(not stat.S_IMODE(s.st_mode) & ~0o777, "special directory permission bits")
            all_dirs[rel] = {"path": rel, "mode": stat.S_IMODE(s.st_mode)}
            for child in sorted(path.iterdir()):
                visit(child, rel + "/" + child.name)
        else:
            rec, before = hashed(path)
            all_files[rel] = dict(path=rel, mode=stat.S_IMODE(before.st_mode),
                                  original_mtime_ns=str(before.st_mtime_ns),
                                  original_ctime_ns=str(before.st_ctime_ns), **rec)
            states[rel] = stamp(before)
    for root in roots:
        require(len(relative(root).parts) == 1, "explicit roots must be immediate children of the evidence base")
        require(not any(root.startswith(old + "/") or old.startswith(root + "/") for old in roots if old != root),
                "overlapping evidence roots")
        visit(base / root, root)
    return ({"schema": "hepta.proof.review_inventory.v1", "base": str(base),
             "roots": roots, "files": [all_files[k] for k in sorted(all_files)],
             "directories": [all_dirs[k] for k in sorted(all_dirs)],
             "file_count": len(all_files), "file_bytes": sum(x["bytes"] for x in all_files.values()),
             "scope": "All regular files and empty directories in the explicit roots; no binary, failed log, or source-file exclusion."}, states)


def tar_bytes(tar, name, raw, mode=0o644):
    item = tarfile.TarInfo(name)
    item.size, item.mode, item.mtime = len(raw), mode, 0
    tar.addfile(item, io.BytesIO(raw))


def restore(parts_path, destination):
    """Independently join published parts, safely restore, and rehash every file."""
    require(not destination.exists(), "restore destination must be fresh")
    destination.mkdir()
    parts = exact_json(parts_path.read_bytes())
    require(parts["schema"] == "hepta.proof.review_archive_parts.v1", "parts schema")
    require(parts["parts"] and len({x["name"] for x in parts["parts"]}) == len(parts["parts"]), "part inventory")
    joined = destination / "restored-archive.tar.gz"
    total, h = 0, hashlib.sha256()
    with joined.open("xb") as target:
        for index, item in enumerate(parts["parts"], 1):
            require(item["name"] == "proof-review.tar.gz.part%04d" % index, "part sequence")
            path = parts_path.parent / item["name"]
            actual, _ = hashed(path)
            require(actual == {"bytes": item["bytes"], "sha256": item["sha256"]}, "part bytes differ")
            require(0 < item["bytes"] <= 768 * 1024, "part size")
            with path.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    target.write(block)
                    total += len(block)
                    h.update(block)
    require(total == parts["archive"]["bytes"] and h.hexdigest() == parts["archive"]["sha256"], "rejoined archive differs")
    expected_raw = (parts_path.parent / "INVENTORY.json").read_bytes()
    require(digest(expected_raw) == parts["inventory_sha256"], "external inventory drift")
    inventory = exact_json(expected_raw)
    expected = {"evidence/" + x["path"]: x for x in inventory["files"]}
    require(len(expected) == inventory["file_count"], "duplicate inventory file")
    expected_dirs = {"evidence/" + x["path"]: x["mode"] for x in inventory["directories"]}
    expected_dirs.update(evidence=0o755, delivery=0o755)
    delivery_raw = {
        "delivery/INVENTORY.json": expected_raw,
        "delivery/PLAN.json": (parts_path.parent / "PLAN.json").read_bytes(),
        "delivery/RESTORE.py": (parts_path.parent / "RESTORE.py").read_bytes(),
    }
    tree = destination / "tree"
    tree.mkdir()
    seen, restored = set(), []
    with tarfile.open(joined, "r:gz") as tar:
        for member in tar:
            name = member.name
            relative(name)
            require(name not in seen, "duplicate archive member")
            seen.add(name)
            path = tree.joinpath(*PurePosixPath(name).parts)
            if member.isdir():
                require(name in expected_dirs, "unexpected directory")
                require(member.mode == expected_dirs[name], "directory mode record differs")
                require(not path.exists(), "directory repeated or precreated")
                path.mkdir()
                continue
            require(member.isfile() and (name in expected or name in delivery_raw), "unexpected/nonregular archive member")
            require(path.parent.is_dir() and not path.parent.is_symlink(), "uncreated or unsafe parent")
            source = tar.extractfile(member)
            require(source is not None, "missing member bytes")
            d, size = hashlib.sha256(), 0
            with source, path.open("xb") as target:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    target.write(block)
                    d.update(block)
                    size += len(block)
            if name in expected:
                rec = expected[name]
                require(size == member.size == rec["bytes"] and d.hexdigest() == rec["sha256"], "restored evidence differs")
                require(member.mode == rec["mode"], "file mode record differs")
                os.chmod(path, rec["mode"])
                reread, _ = hashed(path)
                require(reread == {"bytes": rec["bytes"], "sha256": rec["sha256"]}, "restored file reread differs")
                restored.append({"path": rec["path"], **reread})
            else:
                raw = delivery_raw[name]
                require(size == len(raw) and d.hexdigest() == digest(raw) and path.read_bytes() == raw, "delivery metadata differs")
    require(seen == set(expected) | set(expected_dirs) | set(delivery_raw), "missing archive member")
    for name in sorted(expected_dirs, key=lambda n: (-len(PurePosixPath(n).parts), n)):
        path = tree.joinpath(*PurePosixPath(name).parts)
        os.chmod(path, expected_dirs[name])
        require(stat.S_IMODE(path.lstat().st_mode) == expected_dirs[name], "restored directory mode differs")
    result = {"schema": "hepta.proof.review_restore.v1", "status": "restored_bytes_verified",
              "proof_qualification_passed": False, "fresh_lean_invocations": 0,
              "archive": {"bytes": total, "sha256": h.hexdigest()},
              "inventory_sha256": digest(expected_raw), "restored_files": len(restored),
              "restored_bytes": sum(x["bytes"] for x in restored),
              "restored_inventory_sha256": digest(encoded(sorted(restored, key=lambda x: x["path"]))) }
    write(destination / "RESULT.json", encoded(result))
    print(json.dumps(result, sort_keys=True), flush=True)


def build(plan_path, plan_sha256):
    start, entered = time.monotonic_ns(), time.time_ns()
    plan_raw = plan_path.read_bytes()
    require(digest(plan_raw) == plan_sha256, "plan hash differs")
    plan = exact_json(plan_raw)
    require(plan["schema"] == "hepta.proof.review_archive_plan.v1", "plan schema")
    base, output = Path(plan["base"]), Path(plan["output"])
    require(base.is_absolute() and output.is_absolute() and not output.exists(), "fresh absolute output required")
    require(output.parent == base and output.name not in plan["roots"], "separate sibling output required")
    output.mkdir()
    result = {"schema": "hepta.proof.review_archive_build.v1", "status": "failed", "passed": False,
              "original_proof_qualification_passed": False, "source_commit": plan["source_commit"],
              "source_tree": plan["source_tree"], "started_unix_ns": str(entered), "failure": None,
              "scope": "Delivery and full byte restoration only; no proof, test, model, or benchmark execution."}
    try:
        write(output / "PLAN.json", plan_raw)
        helper = Path(__file__).read_bytes()
        require(digest(helper) == plan["driver_sha256"], "driver drift")
        write(output / "RESTORE.py", helper)
        inventory, states = collect(base, plan["roots"])
        by_name = {x["path"]: x for x in inventory["files"]}
        for wanted in plan["anchors"]:
            actual = by_name.get(wanted["path"])
            require(actual is not None and actual["bytes"] == wanted["bytes"] and
                    actual["sha256"] == wanted["sha256"], "previously observed evidence anchor differs: " + wanted["path"])
        inv_raw = encoded(inventory)
        result["inventory"] = write(output / "INVENTORY.json", inv_raw)
        require(shutil.disk_usage(output).free >= 2 * inventory["file_bytes"] + 1024 * 1024 * 1024,
                "insufficient space for archive and independent restored tree")
        archive = output / "proof-review.tar.gz"
        with archive.open("xb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=6, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as tar:
                    dirs = {"evidence/" + d["path"]: d["mode"] for d in inventory["directories"]}
                    dirs.update(evidence=0o755, delivery=0o755)
                    for name in sorted(dirs, key=lambda n: (len(PurePosixPath(n).parts), n)):
                        item = tarfile.TarInfo(name)
                        item.type, item.mode, item.mtime = tarfile.DIRTYPE, dirs[name], 0
                        tar.addfile(item)
                    tar_bytes(tar, "delivery/INVENTORY.json", inv_raw)
                    tar_bytes(tar, "delivery/PLAN.json", plan_raw)
                    tar_bytes(tar, "delivery/RESTORE.py", helper)
                    for rec in inventory["files"]:
                        path = base / rec["path"]
                        require(stamp(regular(path)) == states[rec["path"]], "input changed before archiving")
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        with os.fdopen(fd, "rb") as stream:
                            require(stamp(os.fstat(stream.fileno())) == states[rec["path"]], "input open identity differs")
                            item = tarfile.TarInfo("evidence/" + rec["path"])
                            item.mode, item.size, item.mtime = rec["mode"], rec["bytes"], 0
                            tar.addfile(item, stream)
                            require(stamp(os.fstat(stream.fileno())) == states[rec["path"]], "input changed during archive")
                        require(stamp(path.lstat()) == states[rec["path"]], "input changed after archive")
        rec, _ = hashed(archive)
        result["archive"] = {"path": str(archive), **rec}
        parts = []
        with archive.open("rb") as source:
            while True:
                block = source.read(768 * 1024)
                if not block:
                    break
                name = "proof-review.tar.gz.part%04d" % (len(parts) + 1)
                write(output / name, block)
                git = hashlib.sha1(b"blob " + str(len(block)).encode() + b"\0" + block).hexdigest()
                parts.append({"name": name, "bytes": len(block), "sha256": digest(block), "git_blob": git})
        parts_raw = encoded({"schema": "hepta.proof.review_archive_parts.v1", "archive": rec,
                             "inventory_sha256": digest(inv_raw), "parts": parts})
        result["parts"] = write(output / "PARTS.json", parts_raw)
        argv = [sys.executable, "-B", str(output / "RESTORE.py"), "restore",
                str(output / "PARTS.json"), str(output / "independent-restore")]
        before = time.monotonic_ns()
        with (output / "restore.stdout").open("xb") as stdout, (output / "restore.stderr").open("xb") as stderr:
            completed = subprocess.run(argv, stdout=stdout, stderr=stderr, check=False, timeout=600)
        result["restore_command"] = {"argv": argv, "returncode": completed.returncode,
                                     "wall_ns": str(time.monotonic_ns() - before)}
        require(completed.returncode == 0, "independent restoration failed")
        restored = exact_json((output / "independent-restore/RESULT.json").read_bytes())
        require(restored["status"] == "restored_bytes_verified" and restored["archive"] == rec and
                restored["restored_files"] == inventory["file_count"] and
                restored["restored_bytes"] == inventory["file_bytes"] and
                restored["inventory_sha256"] == digest(inv_raw), "restoration receipt differs")
        for rel, original in states.items():
            require(stamp(regular(base / rel)) == original, "original evidence changed during delivery")
        final_files, final_dirs = set(), set()
        def names_only(path, rel):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                final_dirs.add(rel)
                for child in path.iterdir():
                    names_only(child, rel + "/" + child.name)
            else:
                require(stat.S_ISREG(info.st_mode), "new nonregular evidence entry")
                final_files.add(rel)
        for name in plan["roots"]:
            names_only(base / name, name)
        require(final_files == set(states) and final_dirs == {d["path"] for d in inventory["directories"]},
                "original evidence file or directory set changed during delivery")
        result.update(status="archived_and_independently_restored", passed=True,
                      file_count=inventory["file_count"], file_bytes=inventory["file_bytes"],
                      root_count=len(plan["roots"]), part_count=len(parts),
                      original_evidence_file_metadata_unchanged=True,
                      original_evidence_file_and_directory_sets_unchanged=True, restore=restored)
    except BaseException as error:
        result["failure"] = {"type": type(error).__name__, "message": str(error),
                             "traceback": traceback.format_exc()}
    result["finished_unix_ns"] = str(time.time_ns())
    result["wall_ns"] = str(time.monotonic_ns() - start)
    write(output / "RESULT.json", encoded(result))
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("plan", type=Path)
    b.add_argument("sha256")
    r = sub.add_parser("restore")
    r.add_argument("parts", type=Path)
    r.add_argument("destination", type=Path)
    args = parser.parse_args()
    if args.command == "restore":
        restore(args.parts, args.destination)
        return 0
    return build(args.plan, args.sha256)


if __name__ == "__main__":
    raise SystemExit(main())
