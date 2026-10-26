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
from pathlib import Path
import re
import stat
import sys

MAX_SOURCE_BYTES = 1024 * 1024
_SCHEMA_NAME = re.compile(r"SCHEMA(?:_V[1-9][0-9]*)?\Z")
_PROFILE_NAME = re.compile(r"PROFILE(?:_V[1-9][0-9]*)?\Z")
_SCHEMA_VALUE = re.compile(r"hepta\.hia\.program\.v[1-9][0-9]*\Z")


class HIAWireAuditRejected(ValueError):
    pass


def _fail(reason: str) -> None:
    raise HIAWireAuditRejected("E_HIA_SCHEMA_AUDIT: " + reason)


def _read(path: Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_SOURCE_BYTES:
        _fail("expected bounded ordinary source file")
    raw = path.read_bytes()
    after = path.lstat()
    if (len(raw) != info.st_size or (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)):
        _fail("source modified during audit")
    return raw


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
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if any(isinstance(child, ast.Name) and (
                    _SCHEMA_NAME.fullmatch(child.id) or _PROFILE_NAME.fullmatch(child.id))
                    for child in ast.walk(node.target)):
                _fail("annotated/dynamic schema/profile assignment")
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
    return {"sha256": sha256(raw).hexdigest(), "profiles": profiles}


def compare(left: dict, right: dict) -> dict:
    if (type(left) is not dict or type(right) is not dict
            or type(left.get("profiles")) is not list or type(right.get("profiles")) is not list):
        _fail("invalid audit source inventory")
    a = {p["schema"]: p["profile"] for p in left["profiles"]}
    b = {p["schema"]: p["profile"] for p in right["profiles"]}
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
