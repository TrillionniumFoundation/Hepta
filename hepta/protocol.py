"""Snapshot-bound, body-only semantic changes with atomic local writeback.

The transaction protects source and contracts, not effects of external programs.
Validation compiles metadata; it does not execute user programs or run network I/O.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile

from .ast import Diagnostic, HeptaError
from .backend import sha256
from .pipeline import analyze, interface_hash
from .parser import parse


def error(code, message):
    return {"schema": "hepta.patch.v1", "ok": False, "status": "rejected", "diagnostics": [{"code": code, "message": message, "phase": "transaction"}], "applied": False}


def apply_patch(path: str | Path, request: dict, *, apply=False, rustc=None, target=None) -> dict:
    if not isinstance(request, dict):
        return error("E_PATCH_SCHEMA", "The patch request must be a JSON object")
    required = {"schema", "expected_source_sha256", "expected_interface_sha256", "symbol", "replacement_body"}
    if set(request) != required or request.get("schema") != "hepta.patch.v1" or not all(isinstance(request.get(k), str) for k in required):
        return error("E_PATCH_SCHEMA", "Require exactly schema, expected_source_sha256, expected_interface_sha256, symbol and replacement_body")
    file = Path(path).resolve()
    if not file.is_file():
        return error("E_PATCH_FILE", "Source file does not exist")
    original_bytes = file.read_bytes()
    if sha256(original_bytes) != request["expected_source_sha256"]:
        return error("E_STALE_SOURCE", "Source changed since the supplied snapshot")
    try:
        original = original_bytes.decode("utf-8")
        old = parse(original, str(file))
    except (UnicodeDecodeError, HeptaError) as exc:
        return error("E_PATCH_SOURCE", str(exc))
    if interface_hash(old) != request["expected_interface_sha256"]:
        return error("E_STALE_INTERFACE", "Interface/contract snapshot does not match")
    matches = [f for f in old.functions if f.name == request["symbol"] and f.body is not None]
    if len(matches) != 1:
        return error("E_PATCH_SYMBOL", "Patch must identify exactly one implemented function")
    fn = matches[0]
    body = request["replacement_body"]
    candidate = original[:fn.body_span.start] + body + original[fn.body_span.end:]
    checked = analyze(candidate, str(file), rustc=rustc, target=target)
    if not checked.report["ok"]:
        return {"schema": "hepta.patch.v1", "ok": False, "status": "rejected", "applied": False,
                "diagnostics": checked.report["diagnostics"], "validation": checked.report}
    if interface_hash(checked.program) != request["expected_interface_sha256"]:
        return error("E_CONTRACT_CHANGE", "Body replacement changed declarations or contracts")
    newfn = next(f for f in checked.program.functions if f.name == fn.name)
    if candidate[newfn.body_span.start:newfn.body_span.end] != body:
        return error("E_PATCH_SCOPE", "replacement_body must be exactly one brace-delimited body")
    result = {"schema": "hepta.patch.v1", "ok": True, "status": "validated", "applied": False,
              "before_sha256": sha256(original_bytes), "after_sha256": sha256(candidate.encode()),
              "interface_sha256": interface_hash(old), "validation": checked.report,
              "scope": "single_compilation_unit_body_only", "functional_equivalence_proved": False,
              "concurrency": "cooperative_writers_only",
              "external_effects_rolled_back": False}
    if not apply:
        return result
    lock = file.with_name(file.name + ".hepta-lock")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return error("E_PATCH_BUSY", "Another transaction owns the source lock; inspect stale locks before removal")
    staged = None
    try:
        os.write(fd, json.dumps({"pid": os.getpid(), "source_sha256": request["expected_source_sha256"]}).encode())
        if file.read_bytes() != original_bytes:
            return error("E_STALE_SOURCE", "Source changed while validation ran")
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=file.parent, prefix=".hepta-patch-", delete=False) as f:
            staged = Path(f.name)
            f.write(candidate)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(staged, stat.S_IMODE(file.stat().st_mode))
        if file.read_bytes() != original_bytes:
            return error("E_STALE_SOURCE", "Source changed before atomic replacement")
        os.replace(staged, file)
        staged = None
        result["applied"] = True
        result["status"] = "applied"
        return result
    finally:
        os.close(fd)
        lock.unlink(missing_ok=True)
        if staged is not None:
            staged.unlink(missing_ok=True)
