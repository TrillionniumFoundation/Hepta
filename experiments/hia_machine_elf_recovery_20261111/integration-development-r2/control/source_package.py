#!/usr/bin/env python3
"""Export/reconstruct one exact Git commit and its complete tree/blob closure.

This is a source-custody transport. It does not run or grant HIA qualification.
The original commit object is retained, including every parent header. Parent
history is intentionally absent and represented by an explicit shallow boundary.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import traceback


SCHEMA = "hepta.hia.git-source-package.v1"
SCOPE = "EXACT_COMMIT_TREE_BLOB_CLOSURE_WITH_EXPLICIT_SHALLOW_BOUNDARY"
TOOL = "experiments/hia_git_source_package_20261111/source_package.py"
HELPER = "tools/hia_core_source_identity.py"
PACKAGE_FILES = {
    "source.pack", "manifest.json", "source-package.py", "export-report.json",
    "source-state-before.json", "source-state-after.json",
}
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def utc():
    return datetime.now(timezone.utc).isoformat()


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":")) + "\n").encode("ascii")


def no_duplicate_keys(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, "duplicate JSON key: " + name)
        result[name] = value
    return result


def digest(data):
    return hashlib.sha256(data).hexdigest()


def signature(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def regular_file(path, *, collect=False):
    """Read stable regular bytes without following the final path component."""
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), "expected regular file: " + str(path))
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    descriptor = os.open(path, flags)
    contents = [] if collect else None
    checksum = hashlib.sha256()
    blob = hashlib.sha1(b"blob " + str(before.st_size).encode("ascii") + b"\0")
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        require(signature(opened) == signature(before), "file changed before read")
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
            blob.update(block)
            if contents is not None:
                contents.append(block)
        after_fd = os.fstat(stream.fileno())
    require(len({signature(v) for v in (before, opened, after_fd, path.lstat())}) == 1,
            "file changed during read: " + str(path))
    info = {"size": before.st_size, "sha256": checksum.hexdigest(),
            "git_blob_sha1": blob.hexdigest(),
            "mode": "100755" if before.st_mode & stat.S_IXUSR else "100644"}
    return (info, b"".join(contents)) if collect else info


def write_new(path, data):
    with Path(path).open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def environment():
    # None of the caller's Git object/config/namespace overrides may redefine
    # the object database. Do not alter HOME or copy authentication settings.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and k not in {"PYTHONPATH", "PYTHONHOME"}}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
                "GIT_NO_LAZY_FETCH": "1", "PYTHONDONTWRITEBYTECODE": "1",
                "LC_ALL": "C", "TZ": "UTC"})
    return env


def git_command(*arguments):
    return ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
            "-c", "core.autocrlf=false", "-c", "core.fileMode=true",
            "-c", "core.fsmonitor=false", "-c", "gc.auto=0", *map(str, arguments)]


def git(root, *arguments, input=None):
    result = subprocess.run(git_command(*arguments), cwd=root, env=environment(),
                            input=input, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode:
        raise RuntimeError("git " + " ".join(map(str, arguments)) + " failed "
                           + str(result.returncode) + "; stdout="
                           + repr(result.stdout.decode("utf-8", "backslashreplace"))
                           + "; stderr="
                           + repr(result.stderr.decode("utf-8", "backslashreplace")))
    return result.stdout


def path_name(raw):
    name = raw.decode("utf-8")
    require(name and all(p not in {"", ".", "..", ".git"} for p in name.split("/")),
            "unsafe raw Git tree path")
    return name


def tree_inventory(root, tree):
    raw = git(root, "ls-tree", "-r", "-t", "--full-tree", "-z", tree)
    require(not raw or raw.endswith(b"\0"), "incomplete raw tree inventory")
    entries = []
    names = set()
    for record in raw.split(b"\0")[:-1]:
        fields, separator, name = record.partition(b"\t")
        bits = fields.split(b" ")
        require(separator and len(bits) == 3, "malformed raw tree entry")
        mode, kind, oid = (part.decode("ascii") for part in bits)
        require(HEX40.fullmatch(oid), "non-SHA1 tree object")
        require((mode, kind) in {("040000", "tree"), ("100644", "blob"),
                                 ("100755", "blob")},
                "tree member outside original _source_state regular-file profile")
        name = path_name(name)
        require(name not in names, "duplicate raw tree path")
        names.add(name)
        entries.append({"path": name, "mode": mode, "type": kind, "oid": oid})
    return sorted(entries, key=lambda item: item["path"])


def closure(commit, tree, entries):
    objects = {commit: "commit", tree: "tree"}
    for entry in entries:
        prior = objects.setdefault(entry["oid"], entry["type"])
        require(prior == entry["type"], "conflicting object type")
    return objects


def object_inventory(root, expected):
    """Hash each raw object through one streaming cat-file process."""
    records = []
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(git_command("cat-file", "--batch"), cwd=root,
                                   env=environment(), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=errors)
        try:
            for oid, kind in sorted(expected.items()):
                process.stdin.write(oid.encode("ascii") + b"\n")
                process.stdin.flush()
                header = process.stdout.readline()
                fields = header.rstrip(b"\n").split(b" ")
                require(len(fields) == 3 and fields[0].decode("ascii") == oid
                        and fields[1].decode("ascii") == kind
                        and fields[2].isdigit(), "cat-file object header mismatch")
                size = int(fields[2])
                checksum = hashlib.sha256()
                raw_oid = hashlib.sha1(kind.encode("ascii") + b" " + fields[2] + b"\0")
                remaining = size
                while remaining:
                    block = process.stdout.read(min(1024 * 1024, remaining))
                    require(bool(block), "truncated raw Git object")
                    checksum.update(block)
                    raw_oid.update(block)
                    remaining -= len(block)
                require(process.stdout.read(1) == b"\n", "missing cat-file separator")
                require(raw_oid.hexdigest() == oid, "raw Git object hash mismatch")
                records.append({"oid": oid, "type": kind, "size": size,
                                "sha256": checksum.hexdigest()})
            process.stdin.close()
            require(process.stdout.read() == b"", "unexpected cat-file trailing output")
            require(process.wait(timeout=60) == 0, "cat-file failed")
            errors.seek(0)
            require(errors.read() == b"", "cat-file diagnostics")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()
            if not process.stdin.closed:
                process.stdin.close()
    return records


def raw_commit(root, commit):
    raw = git(root, "cat-file", "commit", commit)
    oid = hashlib.sha1(b"commit " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    require(oid == commit, "commit raw bytes differ from requested identity")
    headers = raw.split(b"\n\n", 1)[0].splitlines()
    trees = [line[5:].decode("ascii") for line in headers if line.startswith(b"tree ")]
    parents = [line[7:].decode("ascii") for line in headers if line.startswith(b"parent ")]
    require(len(trees) == 1 and HEX40.fullmatch(trees[0])
            and all(HEX40.fullmatch(p) for p in parents), "malformed commit headers")
    return {"oid": commit, "tree": trees[0], "parents": parents,
            "size": len(raw), "sha256": digest(raw)}


def git_path(root, name):
    result = Path(os.fsdecode(git(root, "rev-parse", "--git-path", name).rstrip(b"\n")))
    return result if result.is_absolute() else root / result


def boundary(root):
    path = git_path(root, "shallow")
    if not path.exists():
        return []
    _, raw = regular_file(path, collect=True)
    require(raw.endswith(b"\n"), "unterminated shallow boundary")
    values = raw.decode("ascii").splitlines()
    require(len(values) == len(set(values)) and all(HEX40.fullmatch(v) for v in values),
            "malformed shallow boundary")
    return sorted(values)


def reject_external_object_state(root):
    for name in ("objects/info/alternates", "objects/info/http-alternates", "info/grafts"):
        require(not git_path(root, name).exists(), "external/grafted object state: " + name)
    require(git(root, "for-each-ref", "--format=%(refname)", "refs/replace") == b"",
            "replacement refs are not package inputs")


def run_original_source_state(root, helper_pin):
    actual = regular_file(root / HELPER)
    require(actual == helper_pin, "original source identity helper changed")
    program = (
        "import json,runpy,sys; "
        "n=runpy.run_path(sys.argv[1]); "
        "s=n['_source_state'](); "
        "print(json.dumps(s,sort_keys=True,ensure_ascii=True,separators=(',',':')))"
    )
    result = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", program,
                             str(root / HELPER)], cwd=root, env=environment(),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(result.returncode == 0,
            "original _source_state failed: " + result.stderr.decode("utf-8", "backslashreplace"))
    require(result.stderr == b"", "original _source_state wrote diagnostics")
    state = json.loads(result.stdout, object_pairs_hook=no_duplicate_keys)
    require(regular_file(root / HELPER) == helper_pin, "source helper changed while executing")
    require(state.get("status") == "", "source worktree is not clean")
    return state


def check_state(state, commit, tree, leaves):
    require(state == {"head": commit, "tree": tree, "status": "",
                      "files": {item["path"]: item["sha256"] for item in leaves}},
            "original _source_state does not equal complete raw leaf inventory")


def leaves_with_hashes(entries, objects):
    table = {item["oid"]: item for item in objects}
    return [{**item, "size": table[item["oid"]]["size"],
             "sha256": table[item["oid"]]["sha256"]}
            for item in entries if item["type"] == "blob"]


def physical_leaves(root, leaves):
    actual = set()
    for current, directories, files in os.walk(root, followlinks=False):
        if Path(current) == root:
            directories.remove(".git")
        for name in directories:
            require(stat.S_ISDIR((Path(current) / name).lstat().st_mode),
                    "non-directory in reconstructed source")
        actual.update((Path(current) / name).relative_to(root).as_posix() for name in files)
    require(actual == {item["path"] for item in leaves}, "physical source leaf set differs")
    for item in leaves:
        info = regular_file(root / item["path"])
        require(info == {"size": item["size"], "sha256": item["sha256"],
                         "git_blob_sha1": item["oid"], "mode": item["mode"]},
                "physical source bytes/mode differ: " + item["path"])


def interpreter():
    path = Path(sys.executable).resolve()
    return {"executable": str(path), "version": sys.version,
            "sha256": regular_file(path)["sha256"]}


def export(root, output, expected_commit):
    root = Path(root).resolve(strict=True)
    output = Path(output).absolute()
    require(HEX40.fullmatch(expected_commit), "expected commit must be full SHA1")
    require(not output.is_relative_to(root), "package output must be outside source")
    require(Path(__file__).resolve() == root / TOOL, "exporter must be the checked-out reviewed tool")
    require(Path(os.fsdecode(git(root, "rev-parse", "--show-toplevel")).strip()).resolve() == root,
            "source root must be repository top level")
    reject_external_object_state(root)
    helper_pin = regular_file(root / HELPER)
    tool_pin = regular_file(root / TOOL)
    before = run_original_source_state(root, helper_pin)
    require(before["head"] == expected_commit, "checkout is not expected exact commit")
    commit = raw_commit(root, expected_commit)
    tree = commit["tree"]
    require(before["tree"] == tree, "source tree changed")
    required_boundary = [expected_commit] if commit["parents"] else []
    source_boundary = boundary(root)
    require(source_boundary == required_boundary, "export requires the real depth-one HEAD boundary")
    require(git(root, "rev-parse", "--is-shallow-repository").strip()
            == (b"true" if required_boundary else b"false"), "shallow status mismatch")
    entries = tree_inventory(root, tree)
    objects = object_inventory(root, closure(expected_commit, tree, entries))
    leaves = leaves_with_hashes(entries, objects)
    check_state(before, expected_commit, tree, leaves)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    report = {"schema": "hepta.hia.git-source-export.v1", "status": "HOLD",
              "scope": SCOPE, "started_utc": utc(), "commit": expected_commit,
              "tree": tree, "interpreter": interpreter(),
              "git_version": git(root, "--version").decode().strip()}
    try:
        write_new(output / "source-state-before.json", canonical(before))
        pack_arguments = ("pack-objects", "--stdout", "--no-reuse-delta",
                          "--window=10", "--depth=50", "--threads=1")
        with (output / "source.pack").open("xb") as stream:
            result = subprocess.run(git_command(*pack_arguments), cwd=root,
                                    env=environment(), input=("\n".join(sorted(closure(
                                        expected_commit, tree, entries))) + "\n").encode("ascii"),
                                    stdout=stream, stderr=subprocess.PIPE, check=False)
            stream.flush()
            os.fsync(stream.fileno())
        require(result.returncode == 0, "pack-objects failed: "
                + result.stderr.decode("utf-8", "backslashreplace"))
        report["pack_command"] = list(pack_arguments)
        report["pack_stderr"] = result.stderr.decode("utf-8", "backslashreplace")
        after = run_original_source_state(root, helper_pin)
        require(after == before, "source identity changed while exporting")
        require(boundary(root) == source_boundary, "source shallow boundary changed")
        require(regular_file(root / TOOL) == tool_pin, "exporter source changed")
        require(tree_inventory(root, tree) == entries, "raw tree changed")
        write_new(output / "source-state-after.json", canonical(after))
        _, consumer = regular_file(root / TOOL, collect=True)
        write_new(output / "source-package.py", consumer)
        pack = regular_file(output / "source.pack")
        manifest = {
            "schema": SCHEMA, "scope": SCOPE, "object_format": "sha1",
            "commit": commit, "tree": tree,
            "shallow": {"source_boundary": source_boundary,
                        "exported_boundary": required_boundary,
                        "ancestor_history_included": False,
                        "original_parent_headers_preserved": True},
            "entries": entries, "objects": objects, "leaves": leaves,
            "counts": {"objects": len(objects), "entries": len(entries),
                       "leaves": len(leaves), "leaf_bytes": sum(x["size"] for x in leaves)},
            "pack": {"file": "source.pack", "size": pack["size"], "sha256": pack["sha256"]},
            "original_source_state_helper": {"path": HELPER, **helper_pin},
            "transport_program": {"path": TOOL, **tool_pin},
            "source_states": {
                name: {"size": regular_file(output / name)["size"],
                       "sha256": regular_file(output / name)["sha256"]}
                for name in ("source-state-before.json", "source-state-after.json")},
        }
        manifest_bytes = canonical(manifest)
        write_new(output / "manifest.json", manifest_bytes)
        report.update({"status": "PASS", "manifest_sha256": digest(manifest_bytes),
                       "pack": manifest["pack"], "counts": manifest["counts"],
                       "source_before_equals_after": True,
                       "qualification_executed": False})
        return report
    except BaseException as exc:
        report["exception"] = {"type": type(exc).__name__, "message": str(exc),
                               "traceback": traceback.format_exc()}
        raise
    finally:
        report["finished_utc"] = utc()
        write_new(output / "export-report.json", canonical(report))


def reproduce_clone(source, destination, manifest, source_state, helper_pin):
    """Exercise Git's real local transport, with neither hardlinks nor alternates."""
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    arguments = ("clone", "--no-local", "--no-hardlinks", "--no-tags", "--no-checkout",
                 "--template=", source.as_uri(), str(destination))
    cloned = subprocess.run(git_command(*arguments), cwd=destination.parent,
                            env=environment(), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    require(cloned.returncode == 0, "actual clone reproduction failed; stdout="
            + repr(cloned.stdout.decode("utf-8", "backslashreplace")) + "; stderr="
            + repr(cloned.stderr.decode("utf-8", "backslashreplace")))
    commit, tree = manifest["commit"]["oid"], manifest["tree"]
    require(git(destination, "rev-parse", "HEAD").decode().strip() == commit,
            "clone did not retain exact HEAD")
    require(raw_commit(destination, commit) == manifest["commit"], "clone rewrote original commit")
    require(boundary(destination) == manifest["shallow"]["exported_boundary"],
            "clone changed shallow boundary")
    reject_external_object_state(destination)
    entries = tree_inventory(destination, tree)
    require(entries == manifest["entries"], "clone raw tree inventory differs")
    expected_objects = closure(commit, tree, entries)
    stored = git(destination, "cat-file", "--batch-all-objects", "--unordered",
                 "--batch-check=%(objectname) %(objecttype)").decode("ascii").splitlines()
    require(sorted(stored) == sorted(oid + " " + kind for oid, kind in expected_objects.items()),
            "clone object database differs from exact closure")
    require(object_inventory(destination, expected_objects) == manifest["objects"],
            "clone raw object bytes differ")
    fsck = subprocess.run(git_command("fsck", "--full", "--strict", "--no-reflogs",
                                      "--no-dangling", commit), cwd=destination,
                          env=environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=False)
    require(fsck.returncode == 0 and fsck.stdout == fsck.stderr == b"", "clone strict fsck failed; "
            + repr((fsck.returncode, fsck.stdout, fsck.stderr)))
    git(destination, "read-tree", "--reset", "-u", commit)
    physical_leaves(destination, manifest["leaves"])
    before = run_original_source_state(destination, helper_pin)
    require(before == source_state, "clone original _source_state differs")
    storage = []
    for root in (source, destination):
        identities = set()
        for current, _, files in os.walk(root / ".git" / "objects"):
            for name in files:
                value = (Path(current) / name).lstat()
                require(stat.S_ISREG(value.st_mode), "nonregular Git object storage")
                identities.add((value.st_dev, value.st_ino))
        storage.append(identities)
    require(not storage[0].intersection(storage[1]), "clone shares object-storage hardlinks")
    after = run_original_source_state(destination, helper_pin)
    require(after == before, "clone source changed during verification")
    return {"status": "PASS", "destination": str(destination), "command": list(arguments),
            "stdout": cloned.stdout.decode("utf-8", "backslashreplace"),
            "stderr": cloned.stderr.decode("utf-8", "backslashreplace"),
            "fsck_full_strict": True, "exact_object_database": True,
            "all_leaves_bytes_modes_verified": True, "object_storage_hardlinks": 0,
            "original_source_state_before": before, "original_source_state_after": after,
            "shallow_boundary": boundary(destination), "ancestor_history_included": False}


def materialize(package, destination, reproduction_destination, expected_commit, expected_tree,
                manifest_sha256):
    package = Path(package).resolve(strict=True)
    destination = Path(destination).absolute()
    reproduction_destination = Path(reproduction_destination).absolute()
    require(not destination.is_relative_to(reproduction_destination)
            and not reproduction_destination.is_relative_to(destination),
            "source and clone destinations must be separate new directories")
    require(HEX40.fullmatch(expected_commit) and HEX40.fullmatch(expected_tree)
            and HEX64.fullmatch(manifest_sha256), "full external identity pins required")
    require(set(p.name for p in package.iterdir()) == PACKAGE_FILES,
            "package file inventory mismatch")
    info, raw = regular_file(package / "manifest.json", collect=True)
    require(info["sha256"] == manifest_sha256, "manifest does not match external SHA256")
    manifest = json.loads(raw, object_pairs_hook=no_duplicate_keys)
    require(manifest["schema"] == SCHEMA and manifest["scope"] == SCOPE
            and manifest["object_format"] == "sha1", "unsupported package scope")
    require(manifest["commit"]["oid"] == expected_commit
            and manifest["commit"]["tree"] == manifest["tree"] == expected_tree,
            "package commit/tree differ from external pins")
    required_boundary = [expected_commit] if manifest["commit"]["parents"] else []
    require(manifest["shallow"] == {
        "source_boundary": required_boundary, "exported_boundary": required_boundary,
        "ancestor_history_included": False, "original_parent_headers_preserved": True},
        "undeclared or altered shallow boundary")
    require(manifest["pack"]["file"] == "source.pack", "pack path must be fixed")
    pack_pin = regular_file(package / "source.pack")
    require({k: pack_pin[k] for k in ("size", "sha256")}
            == {k: manifest["pack"][k] for k in ("size", "sha256")}, "pack identity mismatch")
    require(manifest["transport_program"]["path"] == TOOL
            and manifest["original_source_state_helper"]["path"] == HELPER,
            "transport/helper path changed")
    tool_pin = {k: manifest["transport_program"][k]
                for k in ("size", "sha256", "git_blob_sha1", "mode")}
    # The standalone artifact copy has no executable-bit contract. Its exact
    # bytes must match the reviewed program in the exported source tree.
    for path in (Path(__file__), package / "source-package.py"):
        actual = regular_file(path)
        require(all(actual[k] == tool_pin[k] for k in ("size", "sha256", "git_blob_sha1")),
                "consumer code differs from exported reviewed program")
    source_states = {}
    for name in ("source-state-before.json", "source-state-after.json"):
        observed, content = regular_file(package / name, collect=True)
        require({k: observed[k] for k in ("size", "sha256")} == manifest["source_states"][name],
                "original source-state receipt differs")
        source_states[name] = json.loads(content, object_pairs_hook=no_duplicate_keys)
    require(source_states["source-state-before.json"] == source_states["source-state-after.json"],
            "export source before/after mismatch")
    _, export_raw = regular_file(package / "export-report.json", collect=True)
    exported = json.loads(export_raw, object_pairs_hook=no_duplicate_keys)
    require(exported.get("status") == "PASS" and exported.get("manifest_sha256") == manifest_sha256
            and exported.get("commit") == expected_commit and exported.get("tree") == expected_tree,
            "export did not finish successfully with these exact pins")
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    git(destination, "init", "--quiet", "--object-format=sha1", "--template=",
        "--initial-branch=source-package-unborn")
    for name, value in (("core.hooksPath", os.devnull), ("core.autocrlf", "false"),
                        ("core.fileMode", "true"), ("core.ignoreCase", "false"),
                        ("gc.auto", "0")):
        git(destination, "config", "--local", name, value)
    if required_boundary:
        write_new(destination / ".git" / "shallow",
                  ("\n".join(required_boundary) + "\n").encode("ascii"))
    with (package / "source.pack").open("rb") as stream:
        indexed = subprocess.run(git_command("index-pack", "--stdin", "--strict"),
                                 cwd=destination, env=environment(), stdin=stream,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(indexed.returncode == 0, "index-pack rejected package: "
            + indexed.stderr.decode("utf-8", "backslashreplace"))
    require(raw_commit(destination, expected_commit) == manifest["commit"], "raw original commit mismatch")
    git(destination, "update-ref", "--no-deref", "HEAD", expected_commit)
    detached = subprocess.run(git_command("symbolic-ref", "-q", "HEAD"),
                              cwd=destination, env=environment(), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=False)
    require(detached.returncode == 1 and detached.stdout == detached.stderr == b"",
            "HEAD must be detached")
    fsck = subprocess.run(git_command("fsck", "--full", "--strict", "--no-reflogs",
                                      "--no-dangling", expected_commit),
                          cwd=destination, env=environment(), stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False)
    require(fsck.returncode == 0 and fsck.stdout == fsck.stderr == b"",
            "git fsck --full --strict rejected package; returncode=" + str(fsck.returncode)
            + "; stdout=" + repr(fsck.stdout.decode("utf-8", "backslashreplace"))
            + "; stderr=" + repr(fsck.stderr.decode("utf-8", "backslashreplace")))
    entries = tree_inventory(destination, expected_tree)
    require(entries == manifest["entries"], "complete raw tree inventory mismatch")
    expected_objects = closure(expected_commit, expected_tree, entries)
    stored = git(destination, "cat-file", "--batch-all-objects", "--unordered",
                 "--batch-check=%(objectname) %(objecttype)").decode("ascii").splitlines()
    require(len(stored) == len(set(stored))
            and sorted(stored) == sorted(oid + " " + kind for oid, kind in expected_objects.items()),
            "installed object database is not exactly commit/tree/blob closure")
    objects = object_inventory(destination, expected_objects)
    require(objects == manifest["objects"], "complete object SHA256/size inventory mismatch")
    leaves = leaves_with_hashes(entries, objects)
    require(leaves == manifest["leaves"], "complete leaf inventory mismatch")
    counts = {"objects": len(objects), "entries": len(entries), "leaves": len(leaves),
              "leaf_bytes": sum(x["size"] for x in leaves)}
    require(counts == manifest["counts"], "manifest count mismatch")
    check_state(source_states["source-state-before.json"], expected_commit, expected_tree, leaves)
    git(destination, "read-tree", "--reset", "-u", expected_commit)
    physical_leaves(destination, leaves)
    helper_pin = {k: manifest["original_source_state_helper"][k]
                  for k in ("size", "sha256", "git_blob_sha1", "mode")}
    before = run_original_source_state(destination, helper_pin)
    check_state(before, expected_commit, expected_tree, leaves)
    require(regular_file(destination / TOOL) == tool_pin, "reconstructed transport source mismatch")
    reject_external_object_state(destination)
    require(boundary(destination) == required_boundary, "reconstructed shallow boundary mismatch")
    require(regular_file(package / "source.pack") == pack_pin, "input pack changed during import")
    require(regular_file(package / "manifest.json")["sha256"] == manifest_sha256,
            "manifest changed during import")
    reproduced = reproduce_clone(destination, reproduction_destination, manifest, before, helper_pin)
    after = run_original_source_state(destination, helper_pin)
    require(after == before, "reconstructed source changed at final identity check")
    return {"schema": "hepta.hia.git-source-materialization.v1", "status": "PASS",
            "scope": SCOPE, "commit": expected_commit, "tree": expected_tree,
            "manifest_sha256": manifest_sha256, "pack": manifest["pack"], "counts": counts,
            "destination": str(destination), "interpreter": interpreter(),
            "git_version": git(destination, "--version").decode().strip(),
            "index_pack_stdout": indexed.stdout.decode("ascii"),
            "index_pack_stderr": indexed.stderr.decode("utf-8", "backslashreplace"),
            "fsck_stdout": fsck.stdout.decode("utf-8", "backslashreplace"),
            "fsck_stderr": fsck.stderr.decode("utf-8", "backslashreplace"),
            "fsck_full_strict": True, "exact_object_database": True,
            "all_leaves_bytes_modes_verified": True,
            "original_source_state_before": before, "original_source_state_after": after,
            "original_source_state_matches_export": before == source_states["source-state-before.json"],
            "clone_reproduction": reproduced,
            "original_parent_headers_preserved": True, "shallow_boundary": required_boundary,
            "ancestor_history_included": False, "qualification_executed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    make = commands.add_parser("export")
    make.add_argument("--source-root", required=True)
    make.add_argument("--output-dir", required=True)
    make.add_argument("--expected-commit", required=True)
    take = commands.add_parser("materialize")
    take.add_argument("--package", required=True)
    take.add_argument("--destination", required=True)
    take.add_argument("--reproduction-destination", required=True)
    take.add_argument("--expected-commit", required=True)
    take.add_argument("--expected-tree", required=True)
    take.add_argument("--manifest-sha256", required=True)
    take.add_argument("--report", required=True)
    args = parser.parse_args(argv)
    if args.command == "export":
        result = export(args.source_root, args.output_dir, args.expected_commit)
        print(json.dumps({key: result[key] for key in ("status", "commit", "tree", "manifest_sha256", "counts")}))
        return 0
    report_path = Path(args.report).absolute()
    require(not report_path.exists(), "materialization report must be new")
    require(not report_path.is_relative_to(Path(args.destination).absolute()),
            "materialization report must be outside source")
    require(not report_path.is_relative_to(Path(args.reproduction_destination).absolute()),
            "materialization report must be outside clone reproduction")
    report = {"schema": "hepta.hia.git-source-materialization.v1", "status": "HOLD",
              "started_utc": utc(), "qualification_executed": False}
    try:
        report.update(materialize(args.package, args.destination, args.reproduction_destination,
                                  args.expected_commit, args.expected_tree, args.manifest_sha256))
        print(json.dumps({key: report[key] for key in ("status", "commit", "tree", "counts")}))
        return 0
    except BaseException as exc:
        report["exception"] = {"type": type(exc).__name__, "message": str(exc),
                               "traceback": traceback.format_exc()}
        raise
    finally:
        report["finished_utc"] = utc()
        write_new(report_path, canonical(report))


if __name__ == "__main__":
    raise SystemExit(main())
