"""One bounded, unambiguous intake for caller-authored C resource contracts.

Canonical identity binds the exact declared obligations. It does not infer or
prove pointer validity, and callers must still establish every ABI obligation.
Only ``None`` at the Python API means the default empty scalar contract.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .c_migrate import MigrationRejected
from .hia_json_preflight import preflight_hia_json
from .hia_program_tools import HIAEditRejected, read_bounded

MAX_CONTRACT_BYTES = 1_048_576
MAX_CONTRACT_NODES = 32_768
MAX_CONTRACT_DEPTH = 32
MAX_CONTRACT_STRING_BYTES = 4096


def _reject(code: str, message: str):
    raise MigrationRejected(code, message)


def _envelope(value: dict) -> None:
    schema = value.get("schema")
    if schema == "hepta.c-contracts.v1":
        fields, maps = {"schema", "functions"}, ("functions",)
        code = "E_C_CONTRACT"
    elif schema == "hepta.c-record-views.v1":
        fields, maps = {"schema", "records", "functions"}, ("records", "functions")
        code = "E_C_VIEW_CONTRACT"
    else:
        _reject("E_C_CONTRACT", "Expected an explicit supported C contract schema")
    if set(value) != fields or any(type(value[name]) is not dict for name in maps):
        _reject(code, "Contract envelope has missing, unknown or non-map fields")


def snapshot_contracts(contracts: dict | None) -> dict:
    """Copy a bounded built-in JSON graph before compiler work or observation.

    Do not invoke custom serializers, mapping subclasses or object methods.
    Walk every occurrence, so cyclic graphs and repeated references cannot
    evade budgets. Unknown fields survive the copy and fail schema validation.
    Concurrent caller mutation is not given an atomic point-in-time guarantee;
    every value copied is checked, and only the detached graph is serialized.
    """
    if contracts is None:
        contracts = {"schema": "hepta.c-contracts.v1", "functions": {}}
    if type(contracts) is not dict:
        _reject("E_C_CONTRACT", "C contracts must be an ordinary JSON object")
    root = [None]
    pending = [(contracts, root, 0, 0)]
    nodes = strings_bytes = 0
    try:
        while pending:
            value, parent, key, depth = pending.pop()
            nodes += 1
            if nodes > MAX_CONTRACT_NODES or depth > MAX_CONTRACT_DEPTH:
                _reject("E_C_CONTRACT_LIMIT", "Contract node/depth budget exceeded")
            kind = type(value)
            if kind is dict or kind is list:
                if nodes + len(pending) + len(value) > MAX_CONTRACT_NODES:
                    _reject("E_C_CONTRACT_LIMIT", "Contract node budget exceeded")
                if kind is dict:
                    copied = {}
                    parent[key] = copied
                    for child_key, child in value.items():
                        if type(child_key) is not str:
                            _reject("E_C_CONTRACT_JSON", "Contract object keys must be ordinary strings")
                        strings_bytes += _string_bytes(child_key)
                        pending.append((child, copied, child_key, depth + 1))
                        if nodes + len(pending) > MAX_CONTRACT_NODES or strings_bytes > MAX_CONTRACT_BYTES:
                            _reject("E_C_CONTRACT_LIMIT", "Contract node/text budget exceeded")
                else:
                    copied = []
                    parent[key] = copied
                    for child in value:
                        pending.append((child, copied, len(copied), depth + 1))
                        if nodes + len(pending) > MAX_CONTRACT_NODES:
                            _reject("E_C_CONTRACT_LIMIT", "Contract node budget exceeded")
                        copied.append(None)
            elif kind is str:
                strings_bytes += _string_bytes(value)
                parent[key] = value
            elif kind is int:
                if value.bit_length() > 64:
                    _reject("E_C_CONTRACT_LIMIT", "Contract integer exceeds the 64-bit intake budget")
                parent[key] = value
            elif kind is not bool and kind is not type(None):
                _reject("E_C_CONTRACT_JSON", "Contracts require built-in integer/string/bool/null JSON values")
            else:
                parent[key] = value
            if strings_bytes > MAX_CONTRACT_BYTES:
                _reject("E_C_CONTRACT_LIMIT", "Contract text exceeds byte budget")
        detached = root[0]
        _envelope(detached)
        raw = json.dumps(detached, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(raw) > MAX_CONTRACT_BYTES:
            _reject("E_C_CONTRACT_LIMIT", "Canonical contract exceeds byte budget")
        return detached
    except (UnicodeError, RuntimeError, RecursionError, OverflowError) as exc:
        raise MigrationRejected("E_C_CONTRACT_JSON", "Invalid or concurrently changed contract graph") from exc


def _string_bytes(value: str) -> int:
    if len(value) > MAX_CONTRACT_STRING_BYTES:
        _reject("E_C_CONTRACT_LIMIT", "Contract string exceeds byte budget")
    size = len(value.encode("utf-8"))
    if size > MAX_CONTRACT_STRING_BYTES:
        _reject("E_C_CONTRACT_LIMIT", "Contract string exceeds byte budget")
    return size


def decode_contracts(payload: bytes | str) -> dict:
    """Reject ambiguous or oversized text before allocating its JSON graph."""
    if type(payload) is not bytes and type(payload) is not str:
        _reject("E_C_CONTRACT_JSON", "Contract JSON must be ordinary bytes or text")
    try:
        if len(payload) > MAX_CONTRACT_BYTES:
            _reject("E_C_CONTRACT_LIMIT", "Contract input exceeds byte budget")
        source = payload.decode("utf-8") if type(payload) is bytes else payload
        if len(source.encode("utf-8")) > MAX_CONTRACT_BYTES:
            _reject("E_C_CONTRACT_LIMIT", "Contract input exceeds byte budget")
        # Reuse the existing source-free syntax gate, including duplicate-key
        # detection after Unicode escape decoding. No alternative JSON parser.
        preflight_hia_json(source, max_nodes=MAX_CONTRACT_NODES,
                           max_depth=MAX_CONTRACT_DEPTH)
        value = json.loads(source)
        if type(value) is not dict:
            _reject("E_C_CONTRACT_JSON", "Explicit contract JSON must be an object; null is not omission")
        return snapshot_contracts(value)
    except MigrationRejected:
        raise
    except OverflowError as exc:
        raise MigrationRejected("E_C_CONTRACT_LIMIT", "Contract JSON node/depth budget exceeded") from exc
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise MigrationRejected("E_C_CONTRACT_JSON", "Invalid or ambiguous contract JSON: " + str(exc)) from exc


def load_contracts(path: str | Path) -> dict:
    """Read a bounded ordinary non-symlink file through the shared IO gate."""
    try:
        raw = read_bounded(path, limit=MAX_CONTRACT_BYTES)
    except HIAEditRejected as exc:
        raise MigrationRejected("E_C_CONTRACT_INPUT", "Cannot read bounded ordinary contract input") from exc
    return decode_contracts(raw)


def contract_identity(contracts: dict | None) -> dict:
    value = snapshot_contracts(contracts)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    return {"schema": value["schema"], "canonical_sha256": hashlib.sha256(raw).hexdigest(),
            "canonical_bytes": len(raw), "canonical_encoding": "UTF-8 sorted compact JSON",
            "origin": "caller_declared_not_inferred_or_proved",
            "limits": {"input_bytes": MAX_CONTRACT_BYTES, "nodes": MAX_CONTRACT_NODES,
                       "depth": MAX_CONTRACT_DEPTH, "string_bytes": MAX_CONTRACT_STRING_BYTES}}
