"""Build an explicitly scoped Safe Core shared library with retained proof queries.

All attempts keep their original source and terminal report.  A final program.so
is published only after every final-image SMT obligation passes.  This is an
opt-in candidate entry; it does not change HIA's default native ABI or release.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine
from hepta.hia_safe_core import build_safe_core, _profile


def build(source, output, *, foreign_extent=None, linker="ld", timeout_ms=15000, profile_version=1):
    destination = Path(output).absolute()
    destination.mkdir(parents=False, exist_ok=False)
    started = time.monotonic()
    report = {"schema": "hepta.hia.safe-core-attempt.v1", "ok": False, "status": "running",
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "foreign_extent": foreign_extent, "timeout_ms": timeout_ms, "profile_version": profile_version}
    path = destination / "attempt.json"

    def save():
        path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")

    save()
    try:
        original = Path(source).read_bytes()
        (destination / "source.hia.json").write_bytes(original)
        report["source_sha256"] = sha256(original).hexdigest()
        checked = verify_program(original)
        functions = checked.as_dict()["functions"]
        manifest = () if foreign_extent is None else ((functions[0]["name"], foreign_extent),)
        _profile(checked, foreign_buffer_exports=manifest, profile_version=profile_version)
        (destination / "core.hia.json").write_bytes(checked.canonical_bytes)
        image = emit_program_machine(checked, foreign_buffer_exports=manifest)
        (destination / "candidate.o").write_bytes(image.object_bytes)
        (destination / "candidate.text.bin").write_bytes(image.text_bytes)
        result = build_safe_core(checked, destination / "program.so", foreign_extent=foreign_extent,
                                 linker=linker, timeout_ms=timeout_ms, query_directory=destination / "queries",
                                 profile_version=profile_version)
        report.update(ok=True, status="smt_validated_not_executed", result=result)
    except Exception as exc:
        report.update(status="rejected", error={"type": type(exc).__name__, "message": str(exc),
                                                "counterexample": getattr(exc, "counterexample", None)})
    finally:
        report.update(completed_utc=datetime.now(timezone.utc).isoformat(),
                      elapsed_seconds=time.monotonic() - started)
        report["final_image_published"] = (destination / "program.so").is_file()
        save()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True, help="new evidence/build directory under an existing parent")
    parser.add_argument("--foreign-extent", type=int)
    parser.add_argument("--linker", default="ld")
    parser.add_argument("--timeout-ms", type=int, default=15000)
    parser.add_argument("--profile-version", type=int, choices=(1, 2), default=1,
                        help="v1 preserves the original scope; v2 also admits u16 and checked unsigned casts")
    args = parser.parse_args(argv)
    report = build(args.source, args.output, foreign_extent=args.foreign_extent,
                   linker=args.linker, timeout_ms=args.timeout_ms, profile_version=args.profile_version)
    print(json.dumps({"ok": report["ok"], "status": report["status"], "output": str(Path(args.output).absolute()),
                      "error": report.get("error"), "elapsed_seconds": report["elapsed_seconds"]}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
