"""Independently validate supplied Core, object and final ELF; retain every attempt.

No compiler, assembler, linker or native code is executed by this command.
Only the explicitly bounded Safe Core profile is admitted.  A passing receipt
binds immutable captured bytes and does not authorize execution or adoption.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program
from hepta.hia_safe_core import validate_safe_core_artifact, SafeCoreRejected, UNPROVED_OBLIGATIONS

MAX_INPUT_BYTES = 8 * 1024 * 1024


def _snapshot(path):
    with Path(path).open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_INPUT_BYTES:
            raise SafeCoreRejected("input must be a nonempty regular file of at most 8 MiB")
        data = stream.read(MAX_INPUT_BYTES + 1)
        after = os.fstat(stream.fileno())
    identity = lambda row: (row.st_dev, row.st_ino, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    if identity(before) != identity(after) or len(data) != before.st_size:
        raise SafeCoreRejected("input changed while capturing immutable bytes")
    return data


def check(source, object_path, image_path, output, *, foreign_extent=None, timeout_ms=15000,
          expected_sha256=None, profile_version=1):
    destination = Path(output).absolute()
    destination.mkdir(parents=False, exist_ok=False)
    started = time.monotonic()
    report = {
        "schema": "hepta.hia.safe-core-artifact-check.v1", "ok": False, "status": "running",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "foreign_extent": foreign_extent, "timeout_ms": timeout_ms, "profile_version": profile_version,
        "inputs": {}, "compiler_invoked": False, "linker_invoked": False,
        "native_execution_observed": False, "adopted": False,
        "unproved_obligations": [dict(row) for row in UNPROVED_OBLIGATIONS],
    }
    path = destination / "attempt.json"

    def save():
        temporary = destination / "attempt.json.tmp"
        temporary.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        os.replace(temporary, path)

    save()
    try:
        snapshots = {}
        pins = {} if expected_sha256 is None else expected_sha256
        if type(pins) is not dict or set(pins) - {"source", "object", "image"}:
            raise SafeCoreRejected("expected identities must name source, object or image")
        for kind, supplied, name in (
            ("source", source, "source.hia.json"),
            ("object", object_path, "candidate.o"),
            ("image", image_path, "candidate.so"),
        ):
            data = _snapshot(supplied)
            (destination / name).write_bytes(data)
            digest = sha256(data).hexdigest()
            snapshots[kind] = data
            report["inputs"][kind] = {"sha256": digest, "bytes": len(data), "snapshot": name}
            if kind in pins and pins[kind] != digest:
                raise SafeCoreRejected("supplied " + kind + " SHA-256 does not match its pinned identity")
        checked = verify_program(snapshots["source"])
        (destination / "core.hia.json").write_bytes(checked.canonical_bytes)
        functions = checked.as_dict()["functions"]
        manifest = () if foreign_extent is None else ((functions[0]["name"], foreign_extent),)
        validation = validate_safe_core_artifact(
            checked, snapshots["object"], snapshots["image"], foreign_buffer_exports=manifest,
            timeout_ms=timeout_ms, query_directory=destination / "queries", profile_version=profile_version)
        report.update(ok=True, status="smt_validated_not_executed", validation=validation)
    except Exception as exc:
        report.update(status="rejected", error={"type": type(exc).__name__, "message": str(exc),
                                                "counterexample": getattr(exc, "counterexample", None)})
    finally:
        report.update(completed_utc=datetime.now(timezone.utc).isoformat(),
                      elapsed_seconds=time.monotonic() - started)
        save()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="primitive Core JSON")
    parser.add_argument("--object", required=True, dest="object_path", help="supplied ELF64 ET_REL")
    parser.add_argument("--image", required=True, dest="image_path", help="supplied final ELF64 ET_DYN")
    parser.add_argument("--output", required=True, help="new evidence directory under an existing parent")
    parser.add_argument("--foreign-extent", type=int)
    parser.add_argument("--timeout-ms", type=int, default=15000)
    parser.add_argument("--profile-version", type=int, choices=(1, 2), default=1,
                        help="v1 preserves the original scope; v2 also admits u16 and checked unsigned casts")
    for kind in ("source", "object", "image"):
        parser.add_argument("--" + kind + "-sha256")
    args = parser.parse_args(argv)
    pins = {kind: getattr(args, kind + "_sha256") for kind in ("source", "object", "image")
            if getattr(args, kind + "_sha256") is not None}
    report = check(args.source, args.object_path, args.image_path, args.output,
                   foreign_extent=args.foreign_extent, timeout_ms=args.timeout_ms, expected_sha256=pins,
                   profile_version=args.profile_version)
    print(json.dumps({"ok": report["ok"], "status": report["status"],
                      "output": str(Path(args.output).absolute()), "inputs": report["inputs"],
                      "error": report.get("error"), "elapsed_seconds": report["elapsed_seconds"]}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
