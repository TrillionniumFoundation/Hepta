#!/usr/bin/env python3
"""Same-budget proof timing evidence; each observation owns a fresh process."""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time


def digest_file(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def child(args):
    tree = Path(args.tree).resolve()
    sys.path.insert(0, str(tree))
    import z3
    from hepta.hia_guarded_batch import candidates, SOLVER_TIMEOUT_MS
    from hepta.hia_optimization import _solver_identity
    from hepta.hia_program import verify_program
    from hepta.hia_translation_validation import validate_translation

    def sources():
        return {str(path.relative_to(tree)): digest_file(path)
                for path in sorted((tree / "hepta").glob("*.py"))}

    bank = candidates()
    before, after = bank["baseline"], bank[args.candidate]
    left, right = verify_program(before), verify_program(after)
    source_before = sources()
    solver = _solver_identity(z3)
    started = time.monotonic_ns()
    receipt = validate_translation(before, after, function="calculate", timeout_ms=SOLVER_TIMEOUT_MS)
    elapsed = time.monotonic_ns() - started
    source_after = sources()
    record = {
        "schema": "hepta.hia.guard-partition-proof-observation.v1",
        "tree": str(tree), "candidate": args.candidate, "trial": args.trial,
        "timeout_ms": SOLVER_TIMEOUT_MS, "proof_call_wall_ns": elapsed,
        "before_sha256": left.sha256, "after_sha256": right.sha256,
        "before_input_sha256": left.input_sha256, "after_input_sha256": right.input_sha256,
        "candidate_bank_sha256": sha256(json.dumps(bank, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "source_before": source_before, "source_after": source_after,
        "source_stable": source_before == source_after,
        "solver_identity": solver, "python": {"executable": sys.executable,
            "sha256": digest_file(sys.executable), "version": sys.version},
        "host": {"platform": platform.platform(), "machine": platform.machine()},
        "receipt": receipt,
    }
    print(json.dumps(record, sort_keys=True))


def campaign(args):
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    roots = {"original": str(Path(args.baseline).resolve()),
             "patched": str(Path(args.patched).resolve())}
    rows = []
    for trial in range(args.trials):
        for candidate in ("guard_denominator_8", "guard_denominator_10"):
            # Alternate order to expose order/cache effects. No timing-based
            # retries, discarded failures or acceptance thresholds are used.
            for arm in (("original", "patched") if trial % 2 == 0 else ("patched", "original")):
                command = [sys.executable, str(Path(__file__).resolve()), "--child",
                           "--tree", roots[arm], "--candidate", candidate, "--trial", str(trial)]
                started = time.monotonic_ns()
                result = subprocess.run(command, text=True, capture_output=True, timeout=45)
                elapsed = time.monotonic_ns() - started
                row = {"arm": arm, "trial": trial, "candidate": candidate,
                       "command": command, "returncode": result.returncode,
                       "outer_process_wall_ns": elapsed,
                       "stdout": result.stdout, "stderr": result.stderr}
                if result.returncode == 0:
                    row["observation"] = json.loads(result.stdout)
                rows.append(row)
                (out / f"{trial}-{candidate}-{arm}.json").write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
                print(json.dumps({"arm": arm, "candidate": candidate, "trial": trial,
                    "returncode": result.returncode,
                    "wall_ns": row.get("observation", {}).get("proof_call_wall_ns"),
                    "status": row.get("observation", {}).get("receipt", {}).get("status")} ), flush=True)
    groups = []
    for candidate in ("guard_denominator_8", "guard_denominator_10"):
        for arm in roots:
            chosen = [r for r in rows if r["candidate"] == candidate and r["arm"] == arm]
            good = [r["observation"] for r in chosen if "observation" in r]
            groups.append({"candidate": candidate, "arm": arm,
                "statuses": dict(Counter(r["receipt"]["status"] for r in good)),
                "process_failure_count": sum(r["returncode"] != 0 for r in chosen),
                "proof_call_wall_ns": [r["proof_call_wall_ns"] for r in good],
                "median_proof_call_wall_ns": statistics.median(r["proof_call_wall_ns"] for r in good) if good else None})
    observations = [r["observation"] for r in rows if "observation" in r]
    result = {"schema": "hepta.hia.guard-partition-proof-timing.v1", "groups": groups,
        "trials": args.trials, "timeout_ms": 10000, "child_count": len(rows),
        "fresh_python_process_per_observation": True,
        "same_candidate_bank": len({r["candidate_bank_sha256"] for r in observations}) == 1,
        "all_sources_stable": all(r["source_stable"] for r in observations),
        "same_solver_identity": len({json.dumps(r["solver_identity"], sort_keys=True) for r in observations}) == 1,
        "script_sha256": digest_file(__file__),
        "scope": "Local proof-call timings on a shared Linux host; fresh Python processes, warm OS caches possible. No native performance or production P0-P7 closure claim.",
        "unknown_policy": "Solver unknowns and process failures retained verbatim; no substitution by sampled cases or timing-based retries."}
    (out / "SUMMARY.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--tree")
    parser.add_argument("--candidate")
    parser.add_argument("--trial", type=int, default=0)
    parser.add_argument("--baseline")
    parser.add_argument("--patched")
    parser.add_argument("--output")
    parser.add_argument("--trials", type=int, default=3)
    args = parser.parse_args()
    child(args) if args.child else campaign(args)
