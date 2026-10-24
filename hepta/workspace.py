"""Durable multi-file Agent transactions over immutable, content-addressed trees.

Readers pin one version, writers validate a complete candidate then atomically
publish ONE CURRENT reference. Mutable checkouts are not the transaction store.
POSIX flock/fsync/rename semantics and cooperative readers/writers are required;
this is not a filesystem sandbox against a malicious same-user process.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import fields, is_dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import uuid

from .ast import Expr, HeptaError, Span, Stmt
from .modules import load_project
from .parser import parse
from .pipeline import analyze_project, compiler_hash, interface_hash

SCHEMA = "hepta.workspace.v1"
PATCH_SCHEMA = "hepta.patch.v4"
MAX_FILES = 1024
MAX_BYTES = 16 * 1024 * 1024


class WorkspaceError(ValueError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def fail(code, message):
    raise WorkspaceError(code, message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def relative(value):
    if (not isinstance(value, str) or not value or "\\" in value
            or "\0" in value or PurePosixPath(value).is_absolute()
            or any(p in {"", ".", ".."} for p in value.split("/"))):
        fail("E_WORKSPACE_PATH", "Require a normalized, relative POSIX path")
    return value


def _fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def _atomic_json(path, value):
    staging = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    try:
        _write(staging, canonical(value) + b"\n")
        os.replace(staging, path)
        _fsync_dir(path.parent)
    finally:
        staging.unlink(missing_ok=True)


def _files(root):
    result, total = {}, 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        names.sort()
        for name in list(dirs):
            p = Path(directory) / name
            if p.is_symlink():
                fail("E_WORKSPACE_SYMLINK", "Snapshot directories cannot be symlinks: " + str(p))
            if name in {".git", "__pycache__"}:
                dirs.remove(name)
        for name in names:
            p = Path(directory) / name
            if name == ".git":  # Git worktree pointer, never a project input.
                continue
            if p.is_symlink() or not p.is_file():
                fail("E_WORKSPACE_SYMLINK", "Snapshot inputs must be regular files: " + str(p))
            size = p.stat().st_size
            total += size
            if len(result) >= MAX_FILES or total > MAX_BYTES:
                fail("E_WORKSPACE_LIMIT", "Snapshot exceeds 1024 files or 16 MiB; select a smaller project bundle")
            data = p.read_bytes()
            if len(data) != size:
                fail("E_WORKSPACE_RACE", "Input size changed while capturing: " + str(p))
            result[p.relative_to(root).as_posix()] = data
    return result


def _identity(entry, files, profile):
    return digest(canonical({"entry": entry, "profile": profile,
                             "files": {p: digest(b) for p, b in sorted(files.items())}}))


def _relocate(value, old, new):
    """Retain useful diagnostic/source paths after a staging tree is moved."""
    if isinstance(value, str):
        return new + value[len(old):] if value == old or value.startswith(old + "/") else value
    if isinstance(value, list):
        return [_relocate(v, old, new) for v in value]
    if isinstance(value, dict):
        return {_relocate(k, old, new): _relocate(v, old, new) for k, v in value.items()}
    return value


def _contained(project, root):
    if any(not Path(p).is_relative_to(root) for p in project.sources):
        fail("E_WORKSPACE_ESCAPE", "Capture the entire dependency graph inside the explicit bundle root")
    if project.package_state:
        owner = project.package.root
        if any(not (owner / p).resolve().is_relative_to(root) for p in project.package_state["files"]):
            fail("E_WORKSPACE_ESCAPE", "Package dependencies escape the captured bundle")
    for item in project.c_imports:
        metadata = json.loads(Path(item["manifest"]).read_bytes())
        header = Path(metadata["header"])
        if metadata.get("header_path_kind") == "relative_to_manifest":
            header = Path(item["manifest"]).parent / header
        if not header.resolve().is_relative_to(root) or not header.is_file():
            fail("E_WORKSPACE_FOREIGN_INPUT", "C import headers must be captured inside the bundle")


def _portable_imports(files, root):
    out = dict(files)
    for name, data in files.items():
        if not name.endswith(".hepta.imports.json"):
            continue
        metadata = json.loads(data)
        if metadata.get("schema") != "hepta.c-import.v1":
            fail("E_WORKSPACE_FOREIGN_INPUT", "Unknown C import metadata")
        h = Path(metadata["header"])
        if metadata.get("header_path_kind") == "relative_to_manifest":
            h = (root / name).parent / h
        h = h.resolve()
        if not h.is_relative_to(root) or h.relative_to(root).as_posix() not in files:
            fail("E_WORKSPACE_FOREIGN_INPUT", "Uncaptured C header")
        if digest(files[h.relative_to(root).as_posix()]) != metadata["header_sha256"]:
            fail("E_WORKSPACE_FOREIGN_INPUT", "C header differs from its probe identity")
        metadata["header"] = os.path.relpath(h, (root / name).parent)
        metadata["header_path_kind"] = "relative_to_manifest"
        out[name] = canonical(metadata) + b"\n"
    return out


@contextmanager
def _writer(store):
    store = Path(store).resolve()
    store.mkdir(parents=True, exist_ok=True)
    lock = store / "WRITE.lock"
    if lock.is_symlink():
        fail("E_WORKSPACE_SYMLINK", "Writer lock cannot be a symlink")
    with lock.open("a+b") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield store
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def _read_json(path):
    if path.is_symlink():
        fail("E_WORKSPACE_SYMLINK", "Metadata cannot be a symlink")
    if path.stat().st_size > MAX_BYTES:
        fail("E_WORKSPACE_LIMIT", "Oversized workspace metadata")
    return json.loads(path.read_bytes())


def pin(store, version=None):
    """Read CURRENT once. A returned tree remains pinned across later commits."""
    store = Path(store).resolve()
    if (store / "versions").is_symlink():
        fail("E_WORKSPACE_SYMLINK", "Version storage directory cannot be a symlink")
    if version is None:
        head = _read_json(store / "CURRENT")
        if not isinstance(head, dict) or set(head) != {"schema", "version"} or head["schema"] != SCHEMA:
            fail("E_WORKSPACE_HEAD", "Malformed CURRENT reference")
        version = head["version"]
    if not isinstance(version, str) or not re.fullmatch(r"[a-f0-9]{64}", version):
        fail("E_WORKSPACE_HEAD", "Invalid version identity")
    location = store / "versions" / version
    if location.is_symlink() or (location / "tree").is_symlink():
        fail("E_WORKSPACE_SYMLINK", "Versions must be stored directories")
    meta = _read_json(location / "snapshot.json")
    if not isinstance(meta, dict) or meta.get("schema") != SCHEMA or meta.get("version") != version:
        fail("E_WORKSPACE_IDENTITY", "Snapshot manifest does not match its reference")
    entry = relative(meta["entry"])
    files = _files(location / "tree")
    if (_identity(entry, files, meta["profile"]) != version
            or meta["profile"] != {"compiler_sha256": meta["compiler_sha256"], "target": meta["target"],
                                   "rustc_sha256": meta["validation"]["backend"]["toolchain"]["executable_sha256"],
                                   "native_target": meta["validation"]["backend"]["target"],
                                   "native_flags": meta["validation"]["backend"]["flags"]}
            or meta["files"] != {p: digest(b) for p, b in sorted(files.items())}):
        fail("E_WORKSPACE_IDENTITY", "Published snapshot bytes changed")
    if entry not in files:
        fail("E_WORKSPACE_ENTRY", "Missing snapshot entry")
    return {"schema": SCHEMA, "version": version, "root": str(location / "tree"),
            "entry": str(location / "tree" / entry), "manifest": meta}


def _stage(store, entry, files, parent, rustc, target):
    versions = store / "versions"
    if versions.is_symlink():
        fail("E_WORKSPACE_SYMLINK", "Version storage directory cannot be a symlink")
    versions.mkdir(exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".prepare-", dir=store))
    try:
        tree = stage / "tree"
        tree.mkdir()
        for name, data in sorted(files.items()):
            _write(tree / relative(name), data)
        project = load_project(tree / entry)
        _contained(project, tree)
        # Snapshot copies get their own content lock. Its bytes enter the ID.
        if project.package is not None:
            from .packages import write_lock
            write_lock(project.package.root)
        analysis = analyze_project(tree / entry, rustc=rustc, target=target)
        if not analysis.report["ok"]:
            report = _relocate(analysis.report, str(tree), "candidate")
            report["source_path_base"] = "candidate_bundle"
            return None, report
        files = _files(tree)
        profile = {"compiler_sha256": compiler_hash(), "target": target,
                   "rustc_sha256": analysis.report["backend"]["toolchain"]["executable_sha256"],
                   "native_target": analysis.report["backend"]["target"],
                   "native_flags": analysis.report["backend"]["flags"]}
        if analysis.report["compiler_sha256"] != profile["compiler_sha256"]:
            fail("E_WORKSPACE_COMPILER", "Compiler changed during candidate validation")
        version = _identity(entry, files, profile)
        report = _relocate(analysis.report, str(tree), str(versions / version / "tree"))
        meta = {"schema": SCHEMA, "version": version, "entry": entry,
                "files": {p: digest(b) for p, b in sorted(files.items())},
                "validated_sources": sorted(Path(p).relative_to(tree).as_posix()
                                            for p in analysis.project.sources if p.endswith(".hepta")),
                "parent": parent, "interface_sha256": interface_hash(analysis.program),
                "compiler_sha256": compiler_hash(), "target": target,
                "profile": profile,
                "validation": report, "functional_equivalence_proved": False}
        _write(stage / "snapshot.json", canonical(meta) + b"\n")
        for directory, _, _ in os.walk(tree, topdown=False):
            _fsync_dir(directory)
        _fsync_dir(stage)
        dest = versions / version
        if dest.exists():
            # Content identity is independent of history; verify before reuse.
            pin(store, version)
        else:
            os.rename(stage, dest)
            _fsync_dir(versions)
        return version, report
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def initialize(store, bundle_root, entry, *, rustc=None, target=None):
    root = Path(bundle_root).resolve()
    entry = relative(entry)
    dest = Path(store).resolve()
    if dest.is_relative_to(root) or root.is_relative_to(dest):
        fail("E_WORKSPACE_LAYOUT", "Store and source bundle must be disjoint directories")
    with _writer(dest):
        if (dest / "CURRENT").exists():
            fail("E_WORKSPACE_EXISTS", "Workspace already initialized")
        original = load_project(root / entry)
        _contained(original, root)
        files = _files(root)
        portable = _portable_imports(files, root)
        version, validation = _stage(dest, entry, portable, None, rustc, target)
        if version is None:
            return {"schema": SCHEMA, "ok": False, "applied": False, "validation": validation}
        if _files(root) != files or not original.unchanged():
            fail("E_WORKSPACE_RACE", "Source bundle changed during capture")
        try:
            _atomic_json(dest / "CURRENT", {"schema": SCHEMA, "version": version})
        except OSError as exc:
            try:
                applied = pin(dest)["version"] == version
            except FileNotFoundError:
                applied = False
            except (WorkspaceError, OSError, ValueError, KeyError, TypeError):
                applied = None
            return {"schema": SCHEMA, "ok": False, "applied": applied,
                    "status": "recovery_required", "candidate_version": version,
                    "diagnostics": [{"code": "E_WORKSPACE_PUBLICATION", "message": str(exc), "phase": "workspace"}]}
        return {"schema": SCHEMA, "ok": True, "applied": True, "snapshot": pin(dest),
                "normalized_c_import_paths": files != portable}


def _nodes(source, path):
    """IDs identify exact snapshot nodes; they are never durable across edits."""
    program = parse(source, path)
    nodes = []
    source_hash = digest(source.encode())
    def add(kind, span, name=None, owner=None):
        identity = {"path": path, "source_sha256": source_hash, "kind": kind,
                    "start": span.start, "end": span.end}
        nodes.append({**identity, "id": digest(canonical(identity)), "symbol": name,
                      "owner": owner, "line": span.line, "column": span.column,
                      "text_sha256": digest(source[span.start:span.end].encode())})
    def walk(node, owner):
        if isinstance(node, Expr):
            add("expression", node.span, owner=owner)
        elif isinstance(node, Stmt):
            add("statement", node.span, owner=owner)
        if is_dataclass(node) and not isinstance(node, Span):
            for f in fields(node):
                if f.name not in {"span", "body_span"}:
                    walk(getattr(node, f.name), owner)
        elif isinstance(node, dict):
            for value in node.values(): walk(value, owner)
        elif isinstance(node, (list, tuple)):
            for value in node: walk(value, owner)
    for decl in [*program.structs, *program.enums, *program.functions]:
        kind = "function" if hasattr(decl, "body") else ("struct" if hasattr(decl, "repr_c") else "enum")
        add(kind, decl.span, decl.name)
        if getattr(decl, "body", None) is not None:
            add("body", decl.body_span, decl.name, decl.name)
            walk(decl.body, decl.name)
    # Parenthesized nodes can share spans. A semantic address must be unique.
    unique = {n["id"]: n for n in nodes}
    return list(unique.values())


def inspect_workspace(store):
    snapshot = pin(store)
    root = Path(snapshot["root"])
    nodes = {p: _nodes((root / p).read_text(), p)
             for p in snapshot["manifest"]["validated_sources"]}
    return {"schema": SCHEMA, "ok": True, "snapshot": snapshot, "nodes": nodes,
            "operations": ["replace_body", "replace_function", "replace_expression", "replace_statement", "replace_struct", "replace_enum"],
            "commit_model": "one_atomic_current_reference_pinned_readers"}


def _materialize(snapshot, request):
    root = Path(snapshot["root"])
    files = _files(root)
    edits = request["edits"]
    if not isinstance(edits, list) or not 1 <= len(edits) <= 128:
        fail("E_PATCH_SCHEMA", "Require 1..128 semantic edits")
    grouped, changes = {}, []
    op_kind = {"replace_body": "body", "replace_function": "function",
               "replace_expression": "expression", "replace_statement": "statement",
               "replace_struct": "struct", "replace_enum": "enum"}
    for edit in edits:
        if (not isinstance(edit, dict) or set(edit) != {"op", "target", "node", "replacement"}
                or any(not isinstance(v, str) for v in edit.values()) or edit["op"] not in op_kind):
            fail("E_PATCH_SCHEMA", "Malformed semantic edit")
        name = relative(edit["target"])
        if name not in files or name not in snapshot["manifest"]["validated_sources"]:
            fail("E_PATCH_FILE", "Edit must target a captured module in the validated import graph")
        source = files[name].decode()
        candidates = [n for n in _nodes(source, name) if n["id"] == edit["node"] and n["kind"] == op_kind[edit["op"]]]
        if len(candidates) != 1:
            fail("E_PATCH_NODE", "Node is stale, missing, or has the wrong operation kind")
        node = candidates[0]
        grouped.setdefault(name, []).append((node, edit["replacement"]))
    for name, replacements in grouped.items():
        source = files[name].decode()
        ordered = sorted(replacements, key=lambda pair: pair[0]["start"])
        if any(a[0]["end"] > b[0]["start"] for a, b in zip(ordered, ordered[1:])):
            fail("E_PATCH_OVERLAP", "Semantic edits cannot overlap")
        for node, replacement in reversed(ordered):
            source = source[:node["start"]] + replacement + source[node["end"]:]
        # Each replacement must remain exactly one node of its promised kind,
        # preventing statement/declaration injection via a body/expression edit.
        actual = _nodes(source, name)
        delta = 0
        for node, replacement in ordered:
            start, end = node["start"] + delta, node["start"] + delta + len(replacement)
            matches = [n for n in actual if n["kind"] == node["kind"] and n["start"] == start and n["end"] == end]
            if len(matches) != 1:
                fail("E_PATCH_SCOPE", "Replacement is not exactly the requested semantic node")
            delta += len(replacement) - (node["end"] - node["start"])
        files[name] = source.encode()
        changes.append({"path": name, "before_sha256": snapshot["manifest"]["files"][name],
                        "after_sha256": digest(files[name]), "nodes": len(replacements)})
    return files, changes


def apply_workspace_patch(store, request, *, apply=False, rustc=None, target=None, _checkpoint=None):
    """Validate and CAS-publish a complete tree. _checkpoint is for crash tests."""
    publication_attempted = False
    candidate_version = None
    try:
        expected_keys = {"schema", "expected_version", "expected_interface_sha256", "interface_policy", "edits"}
        if (not isinstance(request, dict) or set(request) != expected_keys
                or request["schema"] != PATCH_SCHEMA
                or request["interface_policy"] not in {"preserve", "migrate"}):
            fail("E_PATCH_SCHEMA", "Require the complete hepta.patch.v4 schema")
        with _writer(store) as dest:
            before = pin(dest)
            if request["expected_version"] != before["version"]:
                fail("E_STALE_PROJECT", "CURRENT differs from the requested frozen snapshot")
            if request["expected_interface_sha256"] != before["manifest"]["interface_sha256"]:
                fail("E_STALE_INTERFACE", "Interface snapshot differs")
            if before["manifest"]["compiler_sha256"] != compiler_hash():
                fail("E_WORKSPACE_COMPILER", "Compiler changed; initialize a freshly validated workspace")
            if target != before["manifest"]["target"]:
                fail("E_WORKSPACE_TARGET", "Transaction must preserve the initialized target profile")
            files, changes = _materialize(before, request)
            entry = before["manifest"]["entry"]
            version, validation = _stage(dest, entry, files, before["version"], rustc, target)
            if version is None:
                return {"schema": PATCH_SCHEMA, "ok": False, "applied": False,
                        "status": "rejected", "validation": validation}
            after = pin(dest, version)
            if after["manifest"]["profile"] != before["manifest"]["profile"]:
                fail("E_WORKSPACE_TOOLCHAIN", "Transaction native toolchain differs from the initialized profile")
            if request["interface_policy"] == "preserve" and after["manifest"]["interface_sha256"] != request["expected_interface_sha256"]:
                fail("E_CONTRACT_CHANGE", "Use explicit interface_policy=migrate to change contracts")
            # Rehash original immediately before publication; same-user
            # uncooperative mutation is detected, not magically prevented.
            if pin(dest)["version"] != before["version"]:
                fail("E_STALE_PROJECT", "CURRENT changed before publication")
            if apply:
                txn = {"schema": SCHEMA, "before": before["version"], "after": version, "state": "prepared"}
                _atomic_json(dest / "JOURNAL", txn)
                if _checkpoint: _checkpoint("prepared")
                publication_attempted = True
                candidate_version = version
                _atomic_json(dest / "CURRENT", {"schema": SCHEMA, "version": version})
                if _checkpoint: _checkpoint("published")
                _atomic_json(dest / "JOURNAL", {**txn, "state": "committed"})
            return {"schema": PATCH_SCHEMA, "ok": True, "applied": apply,
                    "status": "committed" if apply else "validated", "before": before["version"],
                    "after": version, "changes": changes, "snapshot": after,
                    "interface_changed": after["manifest"]["interface_sha256"] != request["expected_interface_sha256"],
                    "validation": validation, "functional_equivalence_proved": False,
                    "reader_protocol_required": True}
    except (WorkspaceError, HeptaError, OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
        code = exc.code if isinstance(exc, WorkspaceError) else (exc.diagnostic.code if isinstance(exc, HeptaError) else "E_WORKSPACE")
        if publication_attempted:
            # rename can succeed before a directory fsync/journal update fails.
            # Never claim "not applied" after that point without inspecting it.
            try:
                applied = pin(store)["version"] == candidate_version
            except (WorkspaceError, OSError, ValueError, KeyError, TypeError):
                applied = None
            return {"schema": PATCH_SCHEMA, "ok": False, "applied": applied,
                    "status": "recovery_required", "candidate_version": candidate_version,
                    "diagnostics": [{"code": code, "message": str(exc), "phase": "workspace"}]}
        return {"schema": PATCH_SCHEMA, "ok": False, "applied": False, "status": "rejected",
                "diagnostics": [{"code": code, "message": str(exc), "phase": "workspace"}]}


def recover(store):
    """Never replay an uncommitted candidate. CURRENT is the commit point."""
    with _writer(store) as dest:
        current = pin(dest)
        journal_path = dest / "JOURNAL"
        state = "clean"
        if journal_path.exists():
            journal = _read_json(journal_path)
            if (set(journal) != {"schema", "before", "after", "state"} or journal["schema"] != SCHEMA
                    or journal["state"] not in {"prepared", "committed", "aborted"}):
                fail("E_WORKSPACE_JOURNAL", "Malformed transaction journal")
            if current["version"] == journal["after"]:
                pin(dest, journal["after"])
                state = "committed"
            elif current["version"] == journal["before"] and journal["state"] != "committed":
                state = "aborted"
            else:
                fail("E_WORKSPACE_JOURNAL", "Journal is inconsistent with CURRENT")
            _atomic_json(journal_path, {**journal, "state": state})
        # Staging trees have never been published and are safe to discard.
        for candidate in dest.glob(".prepare-*"):
            if candidate.is_dir() and not candidate.is_symlink():
                shutil.rmtree(candidate)
        _fsync_dir(dest)
        return {"schema": SCHEMA, "ok": True, "recovery": state, "snapshot": current}
