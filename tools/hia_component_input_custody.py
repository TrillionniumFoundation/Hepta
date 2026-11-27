"""Bind development authoring inputs separately from a native cold source domain.

This is development orchestration, never an installed native authority. Callers
must first admit the complete cold report with ``admit_cold_build``. A native-v2
report qualifies only its native source manifest; Python builders, retained
models and tests are instead pinned to exact, clean Git blobs. Neither domain
is allowed to impersonate the other.
"""
from hashlib import sha1, sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess

from tools.hia_native_cold_admission import SCHEMA as COLD_SCHEMA, read_json
from tools.hia_native_worker_source_authority import SOURCE_SUFFIXES


SCHEMA = "hepta.hia.component-input-custody.v1"
ROOT = Path(__file__).resolve().parents[1]


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _name(name):
    _require(type(name) is str and 0 < len(name) <= 4095,
             "component input path must be bounded text")
    _require(all(32 <= ord(c) < 127 and c not in '\\"' for c in name)
             and not name.startswith("/")
             and all(part not in ("", ".", "..", ".git") for part in name.split("/")),
             "component input path is not a safe relative path: " + name)
    return name


def _git(root, *args, input_bytes=None):
    environment = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": os.devnull, "GIT_NO_REPLACE_OBJECTS": "1",
                   "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
                   "GIT_LITERAL_PATHSPECS": "1"}
    try:
        result = subprocess.run(["git", "-c", "core.fsmonitor=false", *args],
                                cwd=root, env=environment, input=input_bytes,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("cannot read component authoring Git custody") from exc
    _require(result.returncode == 0, "component authoring Git custody failed: "
             + result.stderr.decode("utf-8", errors="replace")[:1000])
    return result.stdout


def _head(root):
    raw = _git(root, "rev-parse", "--verify", "HEAD^{commit}").strip()
    _require(re.fullmatch(rb"[0-9a-f]{40}", raw) is not None,
             "component authoring must have an exact Git commit")
    return raw.decode("ascii")


def _git_object_identity(kind, raw):
    """Recompute the existing SHA-1 repository's actual object name."""
    return sha1(kind.encode("ascii") + b" " + str(len(raw)).encode("ascii")
                + b"\0" + raw).hexdigest()


def _git_object(root, identity, kind):
    _require(re.fullmatch(r"[0-9a-f]{40}", identity) is not None,
             "invalid component Git object name")
    raw = _git(root, "cat-file", kind, identity)
    _require(_git_object_identity(kind, raw) == identity,
             "component Git " + kind + " identity differs from its raw bytes")
    return raw


def _head_tree(root, head):
    raw = _git_object(root, head, "commit")
    headers = raw.split(b"\n\n", 1)[0].split(b"\n")
    match = re.fullmatch(rb"tree ([0-9a-f]{40})", headers[0])
    _require(match is not None
             and [line for line in headers if line.startswith(b"tree ")] == [headers[0]],
             "component Git commit has no unique root tree")
    return match[1].decode("ascii")


def _tree_entries(root, identity):
    raw = _git_object(root, identity, "tree")
    cursor, entries = 0, {}
    while cursor < len(raw):
        space = raw.find(b" ", cursor)
        end = raw.find(b"\0", space + 1) if space >= cursor else -1
        _require(space > cursor and end > space + 1 and end + 21 <= len(raw),
                 "truncated component Git tree entry")
        mode, name = raw[cursor:space], raw[space + 1:end]
        _require(mode in (b"40000", b"100644", b"100755", b"120000", b"160000")
                 and b"/" not in name and name not in (b".", b"..")
                 and name not in entries,
                 "invalid or repeated component Git tree entry")
        entries[name] = (mode.decode("ascii"), raw[end + 1:end + 21].hex())
        cursor = end + 21
    return entries


def _captured_tree_entries(root, tree, captured):
    """Follow verified directory objects; never trust ls-tree's object labels."""
    cache, result = {}, {}
    for name in sorted(captured):
        parent = tree
        parts = _name(name).split("/")
        for index, part in enumerate(parts):
            if parent not in cache:
                cache[parent] = _tree_entries(root, parent)
            entry = cache[parent].get(part.encode("ascii"))
            _require(entry is not None, "component authoring input is untracked or missing: " + name)
            mode, identity = entry
            if index + 1 < len(parts):
                _require(mode == "40000", "component input parent is not a Git directory: " + name)
                parent = identity
            else:
                _require(mode in ("100644", "100755"),
                         "component input is not a regular Git blob: " + name)
                result[name] = (mode, identity)
    return result


def _regular_bytes(root, name, expected):
    """Walk every component without following symlinks; bound the final read."""
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor = None
    try:
        parts = _name(name).split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=parent)
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and info.st_size == len(expected)
                 and info.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX) == 0,
                 "component input is not an unchanged regular file: " + name)
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(len(expected) + 1)
            after = os.fstat(stream.fileno())
        _require(raw == expected and (info.st_dev, info.st_ino, info.st_size,
                 info.st_mtime_ns, info.st_ctime_ns) == (after.st_dev, after.st_ino,
                 after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                 "component input changed while capturing custody: " + name)
        return bool(info.st_mode & stat.S_IXUSR)
    except OSError as exc:
        raise ValueError("component input contains a symlink or unreadable path: " + name) from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _git_inputs(root, captured):
    _require(root == root.resolve(strict=True), "component authoring root is redirected")
    _require(Path(os.fsdecode(_git(root, "rev-parse", "--show-toplevel").strip())) == root,
             "component authoring root is not the Git worktree root")
    head = _head(root)
    tree = _head_tree(root, head)
    entries = _captured_tree_entries(root, tree, captured)
    _require(not _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=no"),
             "component authoring has uncommitted tracked changes")
    names = sorted(entries)
    batch = _git(root, "cat-file", "--batch", input_bytes=b"".join(
        (entries[name][1] + "\n").encode("ascii") for name in names))
    cursor, result = 0, {}
    for name in names:
        newline = batch.find(b"\n", cursor)
        _require(newline >= cursor, "truncated component Git blob batch")
        header = batch[cursor:newline].decode("ascii").split(" ")
        mode, blob = entries[name]
        raw = captured[name]
        _require(header == [blob, "blob", str(len(raw))],
                 "component Git blob size/type differs: " + name)
        cursor = newline + 1
        _require(batch[cursor:cursor + len(raw)] == raw
                 and batch[cursor + len(raw):cursor + len(raw) + 1] == b"\n",
                 "component authoring bytes differ from the exact Git blob: " + name)
        cursor += len(raw) + 1
        _require(_git_object_identity("blob", raw) == blob,
                 "component Git blob identity differs from its raw bytes: " + name)
        executable = _regular_bytes(root, name, raw)
        _require(executable == (mode == "100755"),
                 "component input executable mode differs from Git: " + name)
        result[name] = {"bytes": len(raw), "sha256": sha256(raw).hexdigest(),
                        "git_blob": blob, "git_mode": mode}
    _require(cursor == len(batch) and _head(root) == head,
             "component authoring Git identity changed during capture")
    return head, tree, result


def capture_component_custody(compiler_bytes, cold_bytes, sources, captured, *, root=ROOT):
    """Capture input custody after the caller's independent cold admission.

    Legacy reports retain their original all-input source-map requirement and
    produce no new receipt. Native reports keep host authoring outside that
    map; all implementation source suffixes must still be cold-qualified.
    """
    _require(type(captured) is dict and captured and type(sources) is dict,
             "component custody requires captured bytes and an admitted source map")
    for name, raw in captured.items():
        _name(name)
        _require(type(raw) is bytes, "component input is not frozen bytes: " + name)
    report = read_json(cold_bytes)
    _require(type(report) is dict and report.get("source_manifest") == sources,
             "component source map differs from its admitted cold report")
    if report.get("schema") != COLD_SCHEMA:
        _require(all(sources.get(name) == sha256(raw).hexdigest()
                     for name, raw in captured.items()),
                 "legacy component inputs are not bound by the complete cold source")
        return None
    _require(type(compiler_bytes) is bytes and report.get("generation_sha256")
             == [sha256(compiler_bytes).hexdigest()] * 3,
             "component compiler differs from its admitted native generations")
    native, authoring = {}, {}
    for name, raw in captured.items():
        if name in sources:
            _require(sources[name] == sha256(raw).hexdigest(),
                     "component native input differs from its cold source: " + name)
            native[name] = raw
        else:
            _require(PurePosixPath(name).suffix not in SOURCE_SUFFIXES,
                     "native implementation source is absent from cold authority: " + name)
            authoring[name] = raw
    head, tree, entries = _git_inputs(Path(root).absolute(), captured)
    return {"schema": SCHEMA, "source_head": head, "source_tree": tree,
            "compiler_sha256": sha256(compiler_bytes).hexdigest(),
            "cold_report_sha256": sha256(cold_bytes).hexdigest(),
            "native_source_manifest_sha256": sha256(_canonical(sources)).hexdigest(),
            "native_inputs": {name: entries[name] for name in sorted(native)},
            "host_authoring_inputs": {name: entries[name] for name in sorted(authoring)},
            "host_authoring_is_native_qualified": False,
            "whole_native_delivery_qualified": False}


def verify_component_custody(custody, compiler_bytes, cold_bytes, sources, captured, *, root=ROOT):
    """Independently rederive every byte/blob/mode and exact scope field."""
    expected = capture_component_custody(compiler_bytes, cold_bytes, sources, captured, root=root)
    _require(_canonical(custody) == _canonical(expected),
             "component input custody changed or contains a false authority claim")
