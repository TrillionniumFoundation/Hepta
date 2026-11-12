"""Bounded whole-file log channel for this source-only operation.

The full private operation is always retained separately by upload-artifact.
This channel may omit complete files for its explicit budget. It never turns
a failed source run into PASS and never emits arbitrary environment contents.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
import json
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from files import json_read, put, read, require, save
from adapt_request import context, fixed_policy, operation_root
from finalize import owner_binding

MAX_RAW = 524288
MAX_STDOUT = 1048576
CHUNK = 8192


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def targets(operation):
    name = operation.name
    outside = operation.parent
    rows = [
        ("readback", outside / (name + ".postprocess.json"), False),
        ("prepare-stderr", outside / (name + ".prepare.stderr.log"), False),
        ("run-stderr", outside / (name + ".run.stderr.log"), False),
        ("finalize-stderr", outside / (name + ".finalize.stderr.log"), False),
        ("source-tests", operation / "actual-source/evidence/source-tests.json", True),
        ("lifecycle", operation / "actual-source/lifecycle.json", False),
        ("wrapper", operation / "actual-source/wrapper.json", False),
        ("owner-request", operation / "actual-source/lifecycle.json.request.json", False),
        ("owner-stderr", operation / "actual-source/lifecycle.json.stderr.log", True),
        ("child-stderr", operation / "actual-source/child.stderr.log", True),
        ("source-unittest", operation / "actual-source/evidence/source-unittest.log", True),
        ("derived-support", operation / "actual-source/evidence/derived-HIA_SELFHOST_CORE_SUPPORT.json", True),
        ("derived-coverage", operation / "actual-source/evidence/derived-HIA_SELFHOST_LANGUAGE_COVERAGE.json", True),
        ("context", operation / "RUN-CONTEXT.json", False),
        ("launch", operation / "LAUNCH.json", False),
        ("preparation", operation / "PREPARATION.json", False),
        ("resource", operation / "actual-source/RESOURCE-OBSERVATION.json", False),
        ("prepare-stdout", outside / (name + ".prepare.stdout.log"), False),
        ("run-stdout", outside / (name + ".run.stdout.log"), False),
        ("finalize-stdout", outside / (name + ".finalize.stdout.log"), False),
        ("owner-stdout", operation / "actual-source/lifecycle.json.stdout.log", True),
        ("child-stdout", operation / "actual-source/child.stdout.log", True),
        ("launcher-final", operation / "actual-source/FINAL.json", True),
        ("worker-report", operation / "actual-source/evidence/report.json", True),
        ("request", operation / "REQUEST.json", False),
        ("source-before", operation / "actual-source/evidence/source-before.json", True),
        ("source-after", operation / "actual-source/evidence/source-after.json", True),
        ("source-physical", operation / "SOURCE-PHYSICAL-PINS.json", False),
    ]
    require(len(rows) == 28 and len({str(row[1]) for row in rows}) == 28, "fixed diagnostic paths differ")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter-checkout", type=Path, required=True)
    parser.add_argument("--control-commit", required=True)
    parser.add_argument("--policy-sha256", required=True)
    args = parser.parse_args()
    policy, adapter = fixed_policy(args)
    current = context(policy)
    operation = operation_root(policy, current)
    closed, closure = False, None
    try:
        request, _, _ = json_read(operation / "REQUEST.json", owned=True)
        require(request["remote_execution_context"] == current
                and request["source_root"] == str(operation / "source")
                and request["evidence_root"] == str(operation / "actual-source")
                and request["qualification_seconds"] == 180 and request["cleanup_seconds"] == 3
                and request["process_owner"]["sha256"] == policy["process_owner"]["sha256"],
                "current diagnostic request binding differs")
        closure = owner_binding(operation, request)
        closed = closure["closed"] is True
    except BaseException:
        closure = {"closed": False, "error": traceback.format_exc()}
    rows, selected, used = [], [], 0
    for index, (label, path, child_output) in enumerate(targets(operation)):
        row = {"index": index, "label": label, "path": str(path), "child_output": child_output}
        rows.append(row)
        if child_output and not closed:
            row.update(status="UNCONFIRMED_OWNER_NOT_READ", reason="No stable child-output custody claim.")
            continue
        try:
            raw, pin = read(path, owned=True)
            row["actual"] = pin
            if used + len(raw) > MAX_RAW:
                row.update(status="OMITTED_WHOLE_FILE_BUDGET",
                           reason="The entire original remains in the separate artifact; no bytes truncated.")
                continue
            row["status"] = "SELECTED_COMPLETE"
            selected.append((index, raw, pin))
            used += len(raw)
        except FileNotFoundError:
            row["status"] = "MISSING"
        except BaseException:
            row.update(status="REFUSED_OR_READ_ERROR", error=traceback.format_exc())
    manifest = {"schema": "hepta.hia.numeric-source83-small-channel.v1",
                "context": current, "adapter": adapter, "owner": closure,
                "raw_cap": MAX_RAW, "stdout_cap": MAX_STDOUT, "chunk_bytes": CHUNK,
                "selected_complete_files": len(selected), "selected_complete_raw_bytes": used,
                "fixed_targets": rows, "complete_operation_custody_claimed": False,
                "qualification_result_changed": False, "full_artifact_recovery_still_required": True}
    parts = [b"HIA_SOURCE83_MANIFEST " + wire(manifest) + b"\n"]
    frames = 0
    for index, raw, pin in selected:
        parts.append(b"HIA_SOURCE83_FILE " + wire({"index": index, "actual": pin}) + b"\n")
        for offset in range(0, len(raw), CHUNK):
            block = raw[offset:offset + CHUNK]
            parts.append(b"HIA_SOURCE83_CHUNK " + wire({"index": index, "offset": offset,
                "size": len(block), "sha256": sha256(block).hexdigest(),
                "base64": base64.b64encode(block).decode("ascii")}) + b"\n")
            frames += 1
        parts.append(b"HIA_SOURCE83_FILE_END " + wire({"index": index, "size": len(raw),
                                                      "sha256": pin["sha256"]}) + b"\n")
    body = b"".join(parts)
    require(used <= MAX_RAW and len(body) + 4096 <= MAX_STDOUT,
            "whole diagnostic channel exceeds its fixed bound; nothing printed")
    stem = operation.parent / operation.name
    manifest_pin = save(stem.with_name(stem.name + ".small.manifest.json"), manifest)
    result = {"schema": "hepta.hia.numeric-source83-small-channel-result.v1",
              "status": "SELECTED_WHOLE_FILE_CHANNEL_READY",
              "context": current, "manifest": manifest_pin,
              "selected_files": len(selected), "raw_bytes": used, "frames": frames,
              "prefix_bytes": len(body), "prefix_sha256": sha256(body).hexdigest(),
              "raw_cap": MAX_RAW, "stdout_cap": MAX_STDOUT,
              "qualification_result_changed": False, "complete_operation_custody_claimed": False,
              "result_body_is_in_artifact_not_in_its_own_frames": True}
    result_pin = save(stem.with_name(stem.name + ".small.RESULT.json"), result)
    output = body + b"HIA_SOURCE83_END " + wire({"result": result_pin,
        "selected_files": len(selected), "raw_bytes": used, "frames": frames,
        "prefix_bytes": len(body), "prefix_sha256": sha256(body).hexdigest(),
        "complete_operation_custody_claimed": False}) + b"\n"
    require(len(output) <= MAX_STDOUT, "final diagnostic stdout exceeds fixed bound")
    put(stem.with_name(stem.name + ".small.stdout.log"), output)
    # All selected originals, the manifest, and RESULT are fully persisted
    # before END is emitted. A transport failure never upgrades qualification.
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
