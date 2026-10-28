"""Snapshot-bound edits and no-replace publication of standalone HIA programs.

All accepted edits are rechecked by the independent program verifier.  The
digest binds a snapshot; it is neither a signature nor a semantic proof.
"""
from __future__ import annotations

import copy
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile

from .artifact_publication import publish_verified
from .hia_json_preflight import preflight_hia_json

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_EDITS = 64
# Agent patch/query envelopes add layers outside the 64-level HIA Core.
# Bound them independently before invoking the recursive stdlib JSON encoder.
MAX_AGENT_JSON_DEPTH = 128
# Textual Agent patch envelopes need a pre-materialization node ceiling too.
# Reuse the existing HIA syntax preflight; no second JSON parser or checker.
MAX_AGENT_JSON_NODES = 262144
PATCH_SCHEMA = "hepta.hia.patch.v1"
PATCH_SCHEMA_V2 = "hepta.hia.patch.v2"


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
        # The old byte-only gate could materialize hundreds of thousands
        # of JSON nodes (or hundreds of nested containers) before applying
        # any structural limits. Run the EXISTING source-free HIA JSON
        # syntax preflight before the stdlib decoder; all edit/publish logic
        # and whole-program verification remain unchanged.
        source = payload.decode("utf-8") if type(payload) is bytes else payload
        try:
            preflight_hia_json(source, max_nodes=MAX_AGENT_JSON_NODES,
                              max_depth=MAX_AGENT_JSON_DEPTH)
        except OverflowError as exc:
            raise HIAEditRejected(
                "E_HIA_EDIT: JSON node/depth budget exceeded before decoding"
            ) from exc
        except ValueError as exc:
            # Keep the bounded syntax reason (including duplicate keys)
            # when the early gate rejects before the object-pairs hook.
            # Never retry the full decoder merely to obtain its diagnostic.
            raise HIAEditRejected("E_HIA_EDIT: invalid JSON: " + str(exc)) from exc
        return json.loads(source, object_pairs_hook=_pairs,
                          parse_constant=lambda value: _reject("nonfinite JSON number"))
    except HIAEditRejected:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise HIAEditRejected("E_HIA_EDIT: invalid JSON") from exc


def _keys(value, expected, label):
    if type(value) is not dict or set(value) != set(expected):
        _reject(label + " requires exactly its declared fields; unknown or missing fields")


def _bounded_json_string_size(value: str, maximum: int, ensure_ascii: bool) -> int:
    """Preflight one JSONEncoder string fragment without materializing it.

    An in-memory string of N control characters can require 6*N encoded
    bytes; non-BMP characters may require 12*N when ensure_ascii=True.
    The existing streamed serializer remains the only encoder and will
    still enforce the complete cumulative output byte budget.
    """
    if len(value) + 2 > maximum:
        _reject("JSON string exceeds byte budget before encoding")
    size = 2  # enclosing JSON quotes
    for char in value:
        point = ord(char)
        if point < 32:
            width = 2 if point in (8, 9, 10, 12, 13) else 6
        elif point in (34, 92):  # quote or backslash
            width = 2
        elif point < 128:
            # CPython json.JSONEncoder escapes DEL (U+007F) as \\u007f
            # when ensure_ascii=True, despite DEL being below U+0080.
            # Without this exception a small raw string can allocate a
            # fragment six times the admitted byte budget before refusal.
            width = 6 if point == 127 and ensure_ascii else 1
        elif 0xd800 <= point <= 0xdfff:
            # ASCII escaping a lone surrogate still yields text rejected by
            # HIA JSON predecode; never serialize that invalid wire form.
            _reject("unpaired Unicode surrogate in UTF-8 JSON")
        elif ensure_ascii:
            width = 6 if point <= 0xffff else 12
        elif point < 0x800:
            width = 2
        elif point < 0x10000:
            width = 3
        else:
            width = 4
        size += width
        if size > maximum:
            _reject("JSON string exceeds byte budget before encoding")
    return size


def bounded_json_wire(value, maximum, *, ensure_ascii=True, sort_keys=True):
    """Stream a bounded in-process JSON snapshot rather than materialize first.

    This is only an input-size gate. It never authenticates or verifies HIA.
    Before building encoder fragments, keep in-memory Agent node admission
    consistent with the textual decoder's smaller structural ceiling.
    """
    if type(maximum) is not int or not 0 <= maximum <= MAX_INPUT_BYTES:
        _reject("invalid JSON output byte budget")
    node_budget = min(maximum, MAX_AGENT_JSON_NODES)
    try:
        # A preflight rejects a giant string *before* JSONEncoder builds
        # one huge escaped fragment. Iterative DFS also rejects cycles.
        pending = [(value, False, 0)]
        active = set()
        nodes, queued = 0, 1
        while pending:
            node, leaving, depth = pending.pop()
            if depth > MAX_AGENT_JSON_DEPTH:
                _reject("JSON input exceeds nesting depth before encoding")
            if leaving:
                active.remove(id(node))
                continue
            queued -= 1
            nodes += 1
            if nodes > node_budget:
                _reject("JSON input exceeds node/byte budget")
            if type(node) in (dict, list, tuple):
                # Check fanout *before* queuing child nodes: a single huge
                # list must not allocate millions of pending DFS entries.
                # Include siblings already queued by ancestor containers.
                # Shared nested lists can otherwise enqueue far more than
                # the total node budget before those nodes are visited.
                if len(node) > node_budget - nodes - queued:
                    _reject("JSON container exceeds queued-node/byte budget")
                queued += len(node)
                if id(node) in active:
                    _reject("cyclic JSON container")
                active.add(id(node))
                pending.append((node, True, depth))
                if type(node) is dict:
                    # Python dict keys can differ while their JSON field names
                    # collide (1 vs "1", True vs "true", None vs "null").
                    # Decode rejects duplicate JSON keys; fail before encoder
                    # materialization instead of producing an unusable wire.
                    wire_keys = set()
                    for key, child in node.items():
                        if type(key) not in (str, int, float, bool, type(None)):
                            _reject("unsupported JSON object key")
                        if type(key) is str:
                            _bounded_json_string_size(key, maximum, ensure_ascii)
                            wire_key = key
                        else:
                            # Match CPython's object-key spelling without
                            # invoking an encoder during the preflight.
                            # Exact types above exclude user conversion hooks;
                            # bool must be handled before integer conversion.
                            if type(key) is bool:
                                wire_key = "true" if key else "false"
                            elif key is None:
                                wire_key = "null"
                            elif type(key) is int:
                                # Refuse excessive decimal materialization
                                # before asking the builtin for its digits.
                                if key.bit_length() > maximum * 4:
                                    _reject("JSON key exceeds numeric byte budget")
                                wire_key = int.__repr__(key)
                            else:  # the only remaining admitted type is float
                                if not math.isfinite(key):
                                    _reject("nonfinite JSON object key")
                                wire_key = float.__repr__(key)
                            if len(wire_key) + 2 > maximum:
                                _reject("JSON key exceeds byte budget")
                        if wire_key in wire_keys:
                            _reject("JSON object key collision after JSON conversion")
                        wire_keys.add(wire_key)
                        pending.append((child, False, depth + 1))
                else:
                    pending.extend((child, False, depth + 1) for child in node)
            elif type(node) is str:
                _bounded_json_string_size(node, maximum, ensure_ascii)
            elif type(node) is int:
                # The encoder emits decimal digits as one fragment; reject
                # obviously excessive integers before producing that string.
                if node.bit_length() > maximum * 4:
                    _reject("JSON integer exceeds byte budget")
            elif type(node) not in (bool, float, type(None)):
                _reject("non-JSON in-process value")
        chunks = []
        count = 0
        encoder = json.JSONEncoder(ensure_ascii=ensure_ascii, sort_keys=sort_keys,
                                   separators=(",", ":"), allow_nan=False)
        for fragment in encoder.iterencode(value):
            encoded = fragment.encode("utf-8")
            count += len(encoded)
            if count > maximum:
                _reject("JSON encoding exceeds byte budget")
            chunks.append(encoded)
        return b"".join(chunks)
    except HIAEditRejected:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise HIAEditRejected("E_HIA_EDIT: invalid bounded JSON") from exc


def function_signature(function, *, include_return_loans=False):
    """Detached presentation/interface view of an already verified function."""
    result = {key: copy.deepcopy(function[key]) for key in ("name", "params", "returns", "effects")}
    if include_return_loans:
        result["return_loans"] = copy.deepcopy(function.get("return_loans", [None] * len(function["returns"])))
    return result


def inspect_program(document):
    from .hia_program import verify_program
    verified = verify_program(document)
    data = verified.as_dict()
    return {
        "schema": ("hepta.hia.inspect.v2" if data["schema"] == "hepta.hia.program.v8"
                   else "hepta.hia.inspect.v1"), "ok": True,
        "program_sha256": verified.sha256, "module": data["module"],
        "input_sha256": getattr(verified, "input_sha256", verified.sha256),
        "normalization": getattr(verified, "normalization_report", None),
        "functions": [{
            **function_signature(fn, include_return_loans=data["schema"] == "hepta.hia.program.v8"),
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
        # Enforce the same 8 MiB cap as text before JSON serialization.
        encoded = bounded_json_wire(request, MAX_INPUT_BYTES,
                                    ensure_ascii=False, sort_keys=False)
        request = decode_json(encoded)
    # v1 remains source-snapshot bound, but is now explicitly
    # interface-preserving. ABI/effect changes require a v2 request with
    # an unambiguous migration policy; no implicit interface expansion.
    if type(request) is not dict:
        _reject("patch must be a structured request")
    schema = request.get("schema")
    if schema == PATCH_SCHEMA:
        _keys(request, {"schema", "expected_sha256", "edits"}, "patch")
        interface_policy = "preserve"
    elif schema == PATCH_SCHEMA_V2:
        _keys(request, {"schema", "expected_sha256", "interface_policy", "edits"}, "patch")
        interface_policy = request["interface_policy"]
        if type(interface_policy) is not str or interface_policy not in {"preserve", "migrate"}:
            _reject("v2 interface_policy must be preserve or migrate")
    else:
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
    before = {f["name"]: function_signature(f, include_return_loans=True)
              for f in original.as_dict()["functions"]}
    after = {f["name"]: function_signature(f, include_return_loans=True)
             for f in verified.as_dict()["functions"]}
    changed = sorted(name for name in set(before) | set(after)
                     if before.get(name) != after.get(name))
    if changed and interface_policy != "migrate":
        _reject("interface change needs explicit v2 migrate policy: " + ", ".join(changed[:8]))
    receipt = {
        "schema": "hepta.hia.patch-result.v1", "ok": True,
        "status": "verified_unpublished", "before_sha256": original.sha256,
        "after_sha256": verified.sha256, "edits": len(edits),
        "edit_domain": "independently_verified_normalized_core",
        "original_input_sha256": getattr(original, "input_sha256", original.sha256),
        "interface_changes": changed,
        "claims": {"whole_module_rechecked": True, "behavior_equivalence_proved": False,
                   "native_executed": False},
    }
    if schema == PATCH_SCHEMA_V2:
        receipt["schema"] = "hepta.hia.patch-result.v2"
        receipt["interface_policy"] = interface_policy
        receipt["claims"]["interface_preserved"] = not changed
        # A complete self-contained Core has no external client graph.
        # Explicit migration only permits, never proves, downstream ABI safety.
        receipt["claims"]["external_callers_revalidated"] = False
    return verified, receipt


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
            "program_sha256": verified.sha256,
            "input_sha256": getattr(verified, "input_sha256", verified.sha256),
            "published_representation": "independently_verified_normalized_core",
            "publication": receipt}
