"""Explicit opt-in CI entry dispatch; this module grants no target qualification.

An existing workflow job may run a different fully pinned driver only when its
own exact selector occurs in the actual push head message. The original caller
continues normally when the selector is absent. Target limits and tests remain
owned by the pinned target driver.
"""
from __future__ import annotations

import hashlib
import json
import os
import operator
from pathlib import Path, PurePosixPath
import re
import runpy
import stat
import sys


def _identity(raw: bytes) -> dict:
    return {
        "bytes": len(raw),
        "gitsha": hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def _source(root: Path, relative: str, expected: dict | None = None) -> tuple[dict, bytes]:
    parts = PurePosixPath(relative)
    if parts.is_absolute() or str(parts) != relative or not parts.parts or any(p in ("", ".", "..") for p in parts.parts):
        raise RuntimeError("invalid routed source path")
    path = root
    for part in parts.parts:
        path = path / part
        if path.is_symlink():
            raise RuntimeError("routed source contains a symlink: " + relative)
    if path.resolve(strict=True) != path or not path.is_relative_to(root):
        raise RuntimeError("routed source escapes exact checkout")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o644:
        raise RuntimeError("routed source must be a regular mode 100644 file")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read()
        closed = os.fstat(stream.fileno())
    after = path.lstat()
    identity = _identity(raw)
    stable = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if not stable(before) == stable(opened) == stable(closed) == stable(after) or len(raw) != after.st_size:
        raise RuntimeError("routed source changed while being read: " + relative)
    row = {"path": relative, "mode": "100644", **identity}
    if expected is not None:
        for key in ("path", "mode", "bytes", "gitsha", "sha256"):
            if row[key] != expected[key]:
                raise RuntimeError("routed target pin mismatch: " + key)
    return row, raw


def dispatch(route: dict, caller_file: str, event_raw: bytes, verified_helper_raw: bytes) -> None:
    """Execute one selected target, then preserve its exit or fail source readback."""
    if os.environ.get("GITHUB_EVENT_NAME") != "push":
        raise RuntimeError("explicit source dispatch requires a push event")
    event = json.loads(event_raw)
    event_file = Path(os.environ["GITHUB_EVENT_PATH"])
    if event_file.read_bytes() != event_raw:
        raise RuntimeError("push event changed before dispatch")
    message = event.get("head_commit", {}).get("message", "")
    selector = route["selector"]
    if not isinstance(message, str) or not selector.startswith("[hia-ci:") or not selector.endswith("]") or selector not in message:
        raise RuntimeError("exact explicit selector absent")
    head = os.environ["GITHUB_SHA"]
    if re.fullmatch(r"[0-9a-f]{40}", head) is None or event.get("after") != head or event.get("head_commit", {}).get("id") != head:
        raise RuntimeError("push event does not identify the checked out head")
    if os.environ["GITHUB_JOB"] != route["job"]:
        raise RuntimeError("explicit selector reached the wrong workflow job")
    root = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    caller = Path(caller_file).resolve(strict=True)
    helper = Path(__file__).resolve(strict=True)
    if caller != root / route["caller_path"]:
        raise RuntimeError("unexpected dispatch caller")
    helper_relative = str(helper.relative_to(root).as_posix())
    caller_row, caller_raw = _source(root, route["caller_path"])
    helper_row, helper_raw = _source(root, helper_relative)
    if helper_raw != verified_helper_raw:
        raise RuntimeError("helper differs from the fully pinned bytes already compiled")
    target_row, target_raw = _source(root, route["target"]["path"], route["target"])
    originals = [(caller_row, caller_raw), (helper_row, helper_raw), (target_row, target_raw)]
    if len({row["path"] for row, _ in originals}) != 3:
        raise RuntimeError("caller helper and target must be distinct")
    receipt = {
        "schema": "hia-explicit-source-entry-route-v1",
        "status": "ENTRY_ROUTING_ONLY",
        "head": head,
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "workflow_job": route["job"],
        "selector": selector,
        "actual_target_scope": route["scope"],
        "source_before": [row for row, _ in originals],
        "target_qualification_claimed_by_router": False,
        "whole_stack_closed": False,
        "installed_activation": False,
    }
    print("HIA_EXPLICIT_SOURCE_ENTRY_BEFORE " + json.dumps(receipt, sort_keys=True), flush=True)
    sys.dont_write_bytecode = True
    primary = None
    primary_traceback = None
    try:
        runpy.run_path(str(root / route["target"]["path"]), run_name="__main__")
    except BaseException as exc:
        if not (isinstance(exc, SystemExit) and (exc.code is None or
                isinstance(exc.code, int) and operator.index(exc.code) == 0)):
            primary = exc
            primary_traceback = exc.__traceback__
    after_error = None
    after_errors = []
    observed = []

    def remember_after(label: str, exc: BaseException) -> None:
        nonlocal after_error
        if after_error is None:
            after_error = exc
        after_errors.append({"scope": label, "class": type(exc).__name__, "message": str(exc)})

    for expected, original in originals:
        try:
            current, raw = _source(root, expected["path"], expected)
            if raw != original:
                raise RuntimeError("routed source full bytes changed after target")
            observed.append(current)
        except BaseException as exc:
            remember_after(expected["path"], exc)
    try:
        if event_file.read_bytes() != event_raw:
            raise RuntimeError("push event changed after target")
    except BaseException as exc:
        remember_after("push-event", exc)
    receipt["source_after"] = observed
    receipt["source_after_errors"] = after_errors
    receipt["target_returned_zero"] = primary is None
    receipt["target_failure_class"] = None if primary is None else type(primary).__name__
    receipt["status"] = ("ENTRY_SOURCE_READBACK_FAILED" if after_error is not None else
                         "ENTRY_RETURNED_ZERO" if primary is None else "ENTRY_PROPAGATES_TARGET_FAILURE")
    try:
        print("HIA_EXPLICIT_SOURCE_ENTRY_AFTER " + json.dumps(receipt, sort_keys=True), flush=True)
    except BaseException as exc:
        remember_after("after-receipt-output", exc)
    if primary is not None:
        if after_error is not None:
            primary.add_note("Additional entry source readback/report failure: " + repr(after_error))
            try:
                print("HIA_EXPLICIT_SOURCE_ENTRY_AFTER_FAILURE " + repr(after_error), file=sys.stderr, flush=True)
            except BaseException:
                pass
        raise primary.with_traceback(primary_traceback)
    if after_error is not None:
        raise after_error
    raise SystemExit(0)
