"""Build a register or SIMD kernel and retain the exact final-image proof.

No native candidate is executed by this command. All attempts retain their
source, selected object and terminal report. Failed proofs publish no library.
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
from hepta.hia_verified_kernel import build_verified_kernel
from tools.check_hia_safe_core import _snapshot


def build(source, output, *, strategy="auto", foreign_extent=None, linker="ld", timeout_ms=15000,
          simd_isa="native"):
    destination = Path(output).absolute()
    destination.mkdir(parents=False, exist_ok=False)
    started = time.monotonic()
    report = {"schema": "hepta.hia.verified-kernel-attempt.v1", "ok": False, "status": "running",
              "started_utc": datetime.now(timezone.utc).isoformat(), "strategy": strategy,
              "foreign_extent": foreign_extent, "timeout_ms": timeout_ms,
              "requested_simd_isa": simd_isa,
              "native_execution_observed": False, "adopted": False}
    report_path = destination / "attempt.json"

    def save():
        report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")

    save()
    try:
        original = _snapshot(source)
        (destination / "source.core.hepta").write_bytes(original)
        report["source_sha256"] = sha256(original).hexdigest()
        checked = verify_program(original)
        (destination / "core.core.hepta").write_bytes(checked.canonical_bytes)
        result = build_verified_kernel(
            checked, destination / "program.so", strategy=strategy, foreign_extent=foreign_extent,
            linker=linker, timeout_ms=timeout_ms, query_directory=destination / "queries",
            artifact_directory=destination, simd_isa=simd_isa)
        report.update(ok=True, status=result["status"], result=result,
                      selected_strategy=result["selected_strategy"],
                      selection_refusals=result["selection_refusals"])
    except Exception as exc:
        report.update(status="rejected", error={"type": type(exc).__name__, "message": str(exc),
                                                "counterexample": getattr(exc, "counterexample", None)})
        validation = getattr(exc, "validation", None)
        if validation is not None:
            report["partial_validation"] = validation
    finally:
        selection_path = destination / "selection.json"
        if selection_path.is_file():
            selection = json.loads(selection_path.read_text())
            report.update(selected_strategy=selection["selected_strategy"],
                          selection_refusals=selection["selection_refusals"])
        report.update(completed_utc=datetime.now(timezone.utc).isoformat(),
                      elapsed_seconds=time.monotonic() - started,
                      final_image_published=(destination / "program.so").is_file())
        save()
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True, help="new build/evidence directory")
    parser.add_argument("--strategy", choices=("auto", "scalar", "simd", "checked"), default="auto")
    parser.add_argument("--foreign-extent", type=int, help="existing checked packed-u32 foreign ABI only")
    parser.add_argument("--linker", default="ld")
    parser.add_argument("--timeout-ms", type=int, default=15000)
    parser.add_argument("--target-isa", choices=("native", "sse2", "avx2", "avx512"), default="native")
    args = parser.parse_args(argv)
    report = build(args.source, args.output, strategy=args.strategy, foreign_extent=args.foreign_extent,
                   linker=args.linker, timeout_ms=args.timeout_ms, simd_isa=args.target_isa)
    print(json.dumps({"ok": report["ok"], "status": report["status"],
                      "selected_strategy": report.get("selected_strategy"),
                      "output": str(Path(args.output).absolute()), "error": report.get("error"),
                      "elapsed_seconds": report["elapsed_seconds"]}, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
