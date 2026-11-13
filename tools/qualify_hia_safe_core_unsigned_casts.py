"""Retain v2 unsigned cast proofs and replay the same original SMT obligations."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from hepta.hia_safe_core import ARTIFACT_PROFILE_V2, ARTIFACT_OBLIGATIONS, _source_identity
from tools.build_hia_safe_core import build
from tools.check_hia_safe_core import check

UNSIGNED_TYPES = ("u8", "u16", "u32", "u64", "usize")


def cast_document(source_type, target_type, *, mode="checked", prior_write=False):
    params = [{"name": "value", "type": source_type}]
    ops = []
    if prior_write:
        params.insert(0, {"name": "bytes", "type": "mutbuf"})
        ops.extend([
            {"op": "const", "args": [], "out": [{"name": "index", "type": "usize"}], "attrs": {"value": 0}},
            {"op": "const", "args": [], "out": [{"name": "byte", "type": "u8"}], "attrs": {"value": 93}},
            {"op": "buffer.store", "args": ["bytes", "index", "byte"], "out": [], "attrs": {}},
        ])
    ops.append({"op": "int.cast", "args": ["value"], "out": [{"name": "answer", "type": target_type}], "attrs": {"mode": mode}})
    if prior_write:
        ops.append({"op": "int.cast", "args": ["answer"], "out": [{"name": "result", "type": "u32"}], "attrs": {"mode": "wrap"}})
    effects = ["write", "trap"] if prior_write else ["trap"] if mode == "checked" else []
    return {"schema": "hepta.hia.program.v8", "module": "safe_unsigned_cast", "functions": [{
        "name": "convert", "params": params, "returns": ["u32" if prior_write else target_type],
        "effects": effects, "entry": "entry", "blocks": [{"id": "entry", "params": params, "ops": ops,
            "term": {"op": "ret", "values": ["result" if prior_write else "answer"]}}]}]}


def _save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def _identity():
    return {**{"hepta/" + n: d for n, d in _source_identity().items()},
            **{n: sha256((ROOT / n).read_bytes()).hexdigest() for n in (
                "tools/qualify_hia_safe_core_unsigned_casts.py", "tools/build_hia_safe_core.py",
                "tools/check_hia_safe_core.py", "tests/test_hia_safe_core_unsigned_casts.py")}}


def qualify(output):
    output = Path(output).absolute()
    output.mkdir(exist_ok=False)
    started, source = time.monotonic(), _identity()
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                          text=True, check=True, timeout=10).stdout.strip()
    report = {"schema": "hepta.hia.safe-core-unsigned-casts-qualification.v1", "ok": False,
        "status": "running", "started_utc": datetime.now(timezone.utc).isoformat(),
        "git_head": head, "source_identity": source, "profile_version": 2,
        "positive": [], "artifact_rechecks": [], "query_replays": [],
        "claims": {"whole_compiler_correctness": False, "general_Core_support": False,
            "machine_checked_hardware_ISA": False, "agent_adoption": False,
            "default_profile_changed": False, "production_activation": False}}
    try:
        cases = [(a + "-to-" + b, cast_document(a, b), None) for a in UNSIGNED_TYPES for b in UNSIGNED_TYPES]
        cases.append(("prior-write-before-narrowing", cast_document("u64", "u16", prior_write=True), 16))
        for name, document, extent in cases:
            path = output / name
            path.mkdir()
            _save(path / "source.core.hepta", document)
            attempt = build(path / "source.core.hepta", path / "build", foreign_extent=extent, profile_version=2)
            report["positive"].append({"case": name, "ok": attempt["ok"], "report": name + "/build/attempt.json"})
            if not attempt["ok"]:
                raise ValueError("positive cast proof failed: " + name)
            validation = attempt["result"]["validation"]
            if (validation["artifact_input_profile"] != ARTIFACT_PROFILE_V2 or
                    tuple((o["name"], o["result"]) for o in validation["obligations"]) != ARTIFACT_OBLIGATIONS):
                raise ValueError("profile or obligation inventory differs: " + name)
            if name in ("u64-to-u16", "u16-to-u64", "prior-write-before-narrowing"):
                independent = check(path / "build/source.core.hepta", path / "build/candidate.o",
                    path / "build/program.so", path / "independent", foreign_extent=extent,
                    expected_sha256={"source": attempt["source_sha256"],
                        "object": validation["subject"]["object_sha256"],
                        "image": validation["subject"]["final_image_sha256"]}, profile_version=2)
                report["artifact_rechecks"].append({"case": name, "ok": independent["ok"], "report": name + "/independent/attempt.json"})
                if not independent["ok"]:
                    raise ValueError("independent recheck failed: " + name)
        import z3
        for path in sorted(output.glob("*/build/queries/*.smt2")):
            original = json.loads(path.with_suffix(".smt2.result.json").read_bytes())
            context = z3.Context()
            solver = z3.Solver(ctx=context)
            solver.set(timeout=15000)
            solver.from_file(str(path))
            observed, digest = str(solver.check()), sha256(path.read_bytes()).hexdigest()
            report["query_replays"].append({"query": str(path.relative_to(output)), "sha256": digest,
                                          "result": observed, "expected": original["expected"]})
            if observed != original["expected"] or digest != original["query_sha256"]:
                raise ValueError("raw query identity or replay differs")
        if len(report["positive"]) != 26 or len(report["query_replays"]) != 130:
            raise ValueError("unsigned-cast qualification inventory is incomplete")
        report["source_unchanged"] = source == _identity()
        if not report["source_unchanged"]:
            raise ValueError("qualification source changed during execution")
        report.update(ok=True, status="passed_scoped_model_validation", distinct_programs=26,
                      original_solver_obligations=130, replayed_same_obligations=130)
    except Exception as exc:
        report.update(status="failed", error={"type": type(exc).__name__, "message": str(exc)})
    finally:
        report.update(completed_utc=datetime.now(timezone.utc).isoformat(), elapsed_seconds=time.monotonic() - started)
        _save(output / "qualification.json", report)
        _save(output / "original-files.json", {str(p.relative_to(output)): {
            "sha256": sha256(p.read_bytes()).hexdigest(), "bytes": p.stat().st_size}
            for p in sorted(output.rglob("*")) if p.is_file()})
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    report = qualify(args.output)
    print(json.dumps({"ok": report["ok"], "status": report["status"], "programs": len(report["positive"]),
        "queries": len(report["query_replays"]), "artifact_rechecks": len(report["artifact_rechecks"]),
        "error": report.get("error"), "elapsed_seconds": report["elapsed_seconds"]}))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
