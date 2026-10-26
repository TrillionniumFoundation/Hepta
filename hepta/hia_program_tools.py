"""Snapshot-bound edits and no-replace publication of standalone HIA programs.

All accepted edits are rechecked by the independent program verifier.  The
digest binds a snapshot; it is neither a signature nor a semantic proof.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from .artifact_publication import publish_verified

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_EDITS = 64
PATCH_SCHEMA = "hepta.hia.patch.v1"


class HIAEditRejected(ValueError):
    pass


def _reject(reason):
    raise HIAEditRejected("E_HIA_EDIT: " + reason)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate JSON field: " + key)
        result[key] = value
    return result


def read_bounded(path, limit=MAX_INPUT_BYTES):
    path = Path(path)
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                _reject("input must be a bounded ordinary file")
            payload = stream.read(limit + 1)
        if len(payload) > limit:
            _reject("input exceeds byte limit")
        return payload
    except OSError as exc:
        raise HIAEditRejected("E_HIA_EDIT: cannot read ordinary input") from exc


def decode_json(payload):
    if type(payload) not in (str, bytes):
        _reject("JSON input must be text or bytes")
    try:
        size = len(payload.encode("utf-8")) if type(payload) is str else len(payload)
        if size > MAX_INPUT_BYTES:
            _reject("JSON input exceeds byte limit")
        return json.loads(payload, object_pairs_hook=_pairs,
                          parse_constant=lambda value: _reject("nonfinite JSON number"))
    except HIAEditRejected:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HIAEditRejected("E_HIA_EDIT: invalid JSON") from exc


def _keys(value, expected, label):
    if type(value) is not dict or set(value) != set(expected):
        _reject(label + " has unknown or missing fields")


def inspect_program(document):
    from .hia_program import verify_program
    verified = verify_program(document)
    data = verified.as_dict()
    return {
        "schema": "hepta.hia.inspect.v1", "ok": True,
        "program_sha256": verified.sha256, "module": data["module"],
        "functions": [{
            "name": fn["name"], "params": fn["params"],
            "returns": fn["returns"], "effects": fn["effects"],
            "blocks": [{"id": block["id"], "params": block["params"],
                        "operations": [{"index": index, **operation}
                                       for index, operation in enumerate(block["ops"])],
                        "term": block["term"]} for block in fn["blocks"]],
        } for fn in data["functions"]],
        "claims": {"native_executed": False, "whole_language_soundness_proved": False},
    }


def apply_program_patch(document, request):
    from .hia_program import verify_program
    original = verify_program(document)
    if type(request) in (str, bytes):
        request = decode_json(request)
    else:
        # Reject unbounded/non-JSON Python values before copying an edit tree.
        try:
            encoded = json.dumps(request, allow_nan=False, ensure_ascii=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise HIAEditRejected("E_HIA_EDIT: invalid patch data") from exc
        request = decode_json(encoded)
    _keys(request, {"schema", "expected_sha256", "edits"}, "patch")
    if request["schema"] != PATCH_SCHEMA:
        _reject("unsupported patch schema")
    expected = request["expected_sha256"]
    if type(expected) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected):
        _reject("invalid expected snapshot digest")
    if expected != original.sha256:
        _reject("stale base snapshot")
    edits = request["edits"]
    if type(edits) is not list or not 1 <= len(edits) <= MAX_EDITS:
        _reject("patch needs 1..64 edits")
    candidate = original.as_dict()
    touched, replaced, granular = set(), set(), set()
    for edit in edits:
        if type(edit) is not dict or type(edit.get("action")) is not str:
            _reject("edit needs an action")
        action = edit["action"]
        if action in {"replace_function", "add_function"}:
            _keys(edit, {"action", "function", "definition"}, "function edit")
        elif action == "replace_operation":
            _keys(edit, {"action", "function", "block", "index", "operation"}, "operation edit")
        elif action == "replace_terminator":
            _keys(edit, {"action", "function", "block", "term"}, "terminator edit")
        else:
            _reject("unknown edit action")
        name = edit["function"]
        if type(name) is not str:
            _reject("function identity must be a string")
        matches = [fn for fn in candidate["functions"] if fn["name"] == name]
        if action == "add_function":
            if matches:
                _reject("added function already exists")
            fn = None
        else:
            if len(matches) != 1:
                _reject("function not found")
            fn = matches[0]
        if action in {"replace_function", "add_function"}:
            definition = edit["definition"]
            if type(definition) is not dict or definition.get("name") != name:
                _reject("function edit must retain its declared identity")
            if name in replaced or name in granular:
                _reject("overlapping whole-function and local edits")
            replaced.add(name)
            if action == "add_function":
                candidate["functions"].append(copy.deepcopy(definition))
            else:
                candidate["functions"][candidate["functions"].index(fn)] = copy.deepcopy(definition)
            continue
        if name in replaced:
            _reject("overlapping whole-function and local edits")
        granular.add(name)
        block_name = edit["block"]
        if type(block_name) is not str:
            _reject("block identity must be a string")
        blocks = [b for b in fn["blocks"] if b["id"] == block_name]
        if len(blocks) != 1:
            _reject("block not found")
        block = blocks[0]
        if action == "replace_operation":
            index = edit["index"]
            if type(index) is not int or not 0 <= index < len(block["ops"]):
                _reject("invalid operation index")
            key = (name, block_name, index)
            if key in touched:
                _reject("duplicate operation edit")
            touched.add(key)
            block["ops"][index] = copy.deepcopy(edit["operation"])
        else:
            key = (name, block_name, "term")
            if key in touched:
                _reject("duplicate terminator edit")
            touched.add(key)
            block["term"] = copy.deepcopy(edit["term"])
    # This rechecks the *whole resulting module*, including all callers and
    # resource obligations.  Neither a valid base nor a digest can waive it.
    verified = verify_program(candidate)
    before = {f["name"]: (f["params"], f["returns"], f["effects"])
              for f in original.as_dict()["functions"]}
    after = {f["name"]: (f["params"], f["returns"], f["effects"])
             for f in verified.as_dict()["functions"]}
    return verified, {
        "schema": "hepta.hia.patch-result.v1", "ok": True,
        "status": "verified_unpublished", "before_sha256": original.sha256,
        "after_sha256": verified.sha256, "edits": len(edits),
        "interface_changes": sorted(name for name in set(before) | set(after)
                                    if before.get(name) != after.get(name)),
        "claims": {"whole_module_rechecked": True, "behavior_equivalence_proved": False,
                   "native_executed": False},
    }


def publish_program(document, destination):
    from .hia_program import verify_program
    verified = verify_program(document)
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        _reject("destination must be a new file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.resolve() != destination.parent:
        _reject("output parent must not traverse symlinks")
    payload = verified.canonical_bytes
    with tempfile.TemporaryDirectory(prefix=".hia-publish-", dir=destination.parent) as folder:
        stage = Path(folder) / "program.hia"
        with stage.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        receipt = publish_verified(stage, destination, payload)
    return {"schema": "hepta.hia.output.v1", "ok": True,
            "status": "verified_program_published", "output": str(destination),
            "program_sha256": verified.sha256, "publication": receipt}
