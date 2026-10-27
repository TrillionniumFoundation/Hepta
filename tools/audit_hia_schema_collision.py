#!/usr/bin/env python3
"""Find incompatible HIA program schema labels across independent producers.

Purely syntactic, source-bound conflict detector. A passing audit NEVER proves
semantic equivalence or authorizes merging two different compiler authorities.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys

MAX_SOURCE_BYTES = 1024 * 1024
_SCHEMA_NAME = re.compile(r"SCHEMA(?:_V[1-9][0-9]*)?\Z")
_PROFILE_NAME = re.compile(r"PROFILE(?:_V[1-9][0-9]*)?\Z")
_SCHEMA_VALUE = re.compile(r"hepta\.hia\.program\.v[1-9][0-9]*\Z")


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")

# Imported or stored reflection helpers can mutate literal SCHEMA/PROFILE
# declarations after the syntactic inventory was read. Reject these names
# even if they are never called under their original spelling.
_REFLECTION_NAMES = frozenset({
    "globals", "locals", "vars", "exec", "eval", "setattr", "delattr",
    "getattr", "__import__",
})



class HIAWireAuditRejected(ValueError):
    pass


def _fail(reason: str) -> None:
    raise HIAWireAuditRejected("E_HIA_SCHEMA_AUDIT: " + reason)


def _read(path: Path) -> bytes:
    """Read one pinned ordinary inode; path changes never redirect the read.

    A pre-open lstat followed by Path.read_bytes() could follow a symlink
    swapped in between those operations. Keep O_NOFOLLOW and verify the same
    file-descriptor identity before and after consuming bounded bytes.
    """
    if not hasattr(os, "O_NOFOLLOW"):
        _fail("no-follow file descriptors are required for source auditing")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_SOURCE_BYTES:
        _fail("expected bounded ordinary source file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(before):
            _fail("source identity changed before audit read")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_SOURCE_BYTES + 1)
        after_fd = os.fstat(fd)
        after_path = path.lstat()
        if (len(raw) != before.st_size or identity(after_fd) != identity(before)
                or not stat.S_ISREG(after_path.st_mode)
                or identity(after_path) != identity(before)):
            _fail("source identity or contents changed during audit")
        return raw
    finally:
        os.close(fd)


def _sensitive(name: object) -> bool:
    return type(name) is str and bool(
        _SCHEMA_NAME.fullmatch(name) or _PROFILE_NAME.fullmatch(name)
    )


def _reject_hidden_rebindings(tree: ast.AST, declared_nodes: set[int]) -> None:
    """Literal-only audit: reject noncanonical bindings, including nested ones.

    Runtime reflection cannot be represented as a trustworthy literal inventory.
    This is a static conflict detector, NOT a proof of runtime module semantics.
    """
    for node in ast.walk(tree):
        # Reject the reflection reference itself, not only direct calls.
        # Aliased builtins and stored/qualified helpers cannot be trusted
        # as a static schema inventory.
        if isinstance(node, ast.Name) and node.id in _REFLECTION_NAMES:
            _fail("dynamic namespace/reflection name cannot be audited")
        if isinstance(node, ast.Attribute) and node.attr in _REFLECTION_NAMES:
            _fail("qualified namespace/reflection attribute cannot be audited")
        if isinstance(node, ast.alias) and node.name in _REFLECTION_NAMES:
            _fail("imported namespace/reflection helper cannot be audited")
        if (isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
                and id(node) not in declared_nodes and _sensitive(node.id)):
            _fail("hidden schema/profile rebinding: " + node.id)
        if isinstance(node, ast.alias):
            bound = node.asname or node.name.split(".")[0]
            if _sensitive(bound):
                _fail("import binds schema/profile authority: " + bound)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and _sensitive(node.name):
            _fail("definition shadows schema/profile authority: " + node.name)
        if isinstance(node, ast.arg) and _sensitive(node.arg):
            _fail("parameter shadows schema/profile authority: " + node.arg)
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            if any(_sensitive(name) for name in node.names):
                _fail("global/nonlocal schema/profile rebinding")
        if isinstance(node, ast.ExceptHandler) and _sensitive(node.name):
            _fail("exception binding shadows schema/profile authority")
        if isinstance(node, (ast.MatchAs, ast.MatchStar)) and _sensitive(node.name):
            _fail("pattern binding shadows schema/profile authority")
        if isinstance(node, ast.MatchMapping) and _sensitive(node.rest):
            _fail("pattern rest binding shadows schema/profile authority")


def _validated_inventory(value: dict) -> dict[str, str]:
    """Fail closed on duplicate/forged-shaped caller inventories.

    The digest is only checked for shape; it never authenticates a producer.
    Real audit evidence must originate from declarations() of pinned source bytes.
    """
    if type(value) is not dict or set(value) != {"sha256", "profiles"}:
        _fail("invalid schema inventory envelope")
    digest, profiles = value["sha256"], value["profiles"]
    if (type(digest) is not str or _DIGEST.fullmatch(digest) is None
            or type(profiles) is not list or not 1 <= len(profiles) <= 128):
        _fail("invalid schema inventory digest/profile count")
    by_schema, seen_names = {}, set()
    for entry in profiles:
        if type(entry) is not dict or set(entry) != {"declaration", "schema", "profile"}:
            _fail("malformed schema inventory entry")
        name, schema, profile = entry["declaration"], entry["schema"], entry["profile"]
        if (type(name) is not str or _SCHEMA_NAME.fullmatch(name) is None
                or type(schema) is not str or _SCHEMA_VALUE.fullmatch(schema) is None
                or type(profile) is not str or not 0 < len(profile) <= 256
                or name in seen_names or schema in by_schema):
            _fail("ambiguous or duplicate schema/profile inventory")
        seen_names.add(name)
        by_schema[schema] = profile
    return by_schema


def declarations(raw: bytes) -> dict:
    """Inspect only top-level literal SCHEMA/PROFILE pairs, not docstrings/comments.

    Never execute repository code. Dynamic assignments and repeated declarations
    are rejected because they cannot be classified safely with this scanner.
    """
    if type(raw) is not bytes or not raw or len(raw) > MAX_SOURCE_BYTES:
        _fail("invalid source byte budget")
    try:
        source = raw.decode("utf-8")
        tree = ast.parse(source)
    except (SyntaxError, UnicodeError, ValueError, RecursionError) as exc:
        raise HIAWireAuditRejected("E_HIA_SCHEMA_AUDIT: invalid Python source") from exc
    values = {}
    declared_nodes: set[int] = set()
    for node in tree.body:
        # Any dynamic, annotated or tuple assignment to a schema name is an
        # unknown contract, not an excuse to infer that the schema is absent.
        if isinstance(node, ast.Assign):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                targets = []
                for target in node.targets:
                    targets.extend(child.id for child in ast.walk(target) if isinstance(child, ast.Name))
                if any(_SCHEMA_NAME.fullmatch(n) or _PROFILE_NAME.fullmatch(n) for n in targets):
                    _fail("noncanonical assignment to schema/profile constant")
                continue
            name = names[0]
            if not (_SCHEMA_NAME.fullmatch(name) or _PROFILE_NAME.fullmatch(name)):
                continue
            if name in values or not isinstance(node.value, ast.Constant) or type(node.value.value) is not str:
                _fail("reassigned or dynamic schema/profile constant: " + name)
            values[name] = node.value.value
            declared_nodes.add(id(node.targets[0]))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if any(isinstance(child, ast.Name) and (
                    _SCHEMA_NAME.fullmatch(child.id) or _PROFILE_NAME.fullmatch(child.id))
                    for child in ast.walk(node.target)):
                _fail("annotated/dynamic schema/profile assignment")
    _reject_hidden_rebindings(tree, declared_nodes)
    profiles = []
    for name, schema in sorted(values.items()):
        if not _SCHEMA_NAME.fullmatch(name):
            continue
        suffix = name.removeprefix("SCHEMA")
        profile_name = "PROFILE" + suffix
        if profile_name not in values:
            _fail("missing semantic profile for " + name)
        if not _SCHEMA_VALUE.fullmatch(schema) or not values[profile_name]:
            _fail("unsupported or empty schema/profile literal")
        profiles.append({"declaration": name, "schema": schema, "profile": values[profile_name]})
    if not profiles:
        _fail("no explicit HIA program schema/profile pair")
    if len({p["schema"] for p in profiles}) != len(profiles):
        _fail("duplicate schema value within one authority")
    result = {"sha256": sha256(raw).hexdigest(), "profiles": profiles}
    _validated_inventory(result)
    return result


def compare(left: dict, right: dict) -> dict:
    a = _validated_inventory(left)
    b = _validated_inventory(right)
    overlapping = sorted(set(a) & set(b))
    conflicting = [{"schema": s, "left_profile": a[s], "right_profile": b[s]}
                   for s in overlapping if a[s] != b[s]]
    return {
        "schema": "hepta.hia-schema-collision-audit.v1",
        "left": left,
        "right": right,
        "shared_schema_labels": overlapping,
        "semantic_profile_collisions": conflicting,
        "status": ("incompatible_schema_label_requires_versioned_adapter"
                   if conflicting else "no_profile_collision_detected_not_semantic_equivalence"),
        "unreviewed_profiles_automatically_compatible": False,
        "safe_to_merge_without_source_and_consumer_review": False,
        "whole_project_blockers_closed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--left", required=True, type=Path, help="One exact checked source producer file")
    parser.add_argument("--right", required=True, type=Path, help="The competing producer file")
    parser.add_argument("--output", required=True, type=Path, help="New JSON output (never overwrite)")
    args = parser.parse_args(argv)
    try:
        report = compare(declarations(_read(args.left)), declarations(_read(args.right)))
        result = json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n"
        with args.output.open("x", encoding="utf-8") as handle:
            handle.write(result)
        print(report["status"])
        return 3 if report["semantic_profile_collisions"] else 0
    except (OSError, HIAWireAuditRejected, TypeError, ValueError, RecursionError) as exc:
        print("E_HIA_SCHEMA_AUDIT: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
