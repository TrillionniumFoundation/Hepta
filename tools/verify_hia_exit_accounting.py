"""Check and retain independent Z3 ledger induction obligations.

UNKNOWN/timeouts and unexpected SAT/UNSAT outcomes fail qualification. Queries
and countermodels are retained, including satisfiable antecedents for every
positive obligation to rule out vacuous preservation claims.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

def check(output):
    import z3
    from formal.hia_exit_accounting import negative_controls, obligations

    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    state, heap, size, positive = obligations()
    results = []

    def run(name, kind, constraints, expected):
        solver = z3.Solver()
        solver.set(timeout=5000, random_seed=0)
        solver.add(*constraints)
        query = output / (name + ".smt2")
        query.write_text(solver.to_smt2(), encoding="utf-8")
        answer = str(solver.check())
        row = {"name": name, "kind": kind, "expected": expected, "answer": answer,
               "query": query.name, "query_sha256": sha256(query.read_bytes()).hexdigest()}
        if answer == "sat":
            row["witness"] = str(solver.model())
        elif answer == "unknown":
            row["reason_unknown"] = solver.reason_unknown()
        results.append(row)
        return answer == expected

    passed = True
    for name, premise, conclusion in positive:
        passed = run(name + "_feasible", "nonvacuity", [premise], "sat") and passed
        passed = run(name, "inductive_obligation", [premise, z3.Not(conclusion)], "unsat") and passed
    for name, premise, conclusion in negative_controls(state, heap):
        passed = run(name, "negative_control", [premise, z3.Not(conclusion)], "sat") and passed
    sources = ("formal/hia_exit_accounting.py", "tools/verify_hia_exit_accounting.py")
    report = {
        "schema": "hepta.hia.exit-accounting-proof.v1", "passed": passed,
        "solver": "z3", "solver_version": z3.get_version_string(),
        "source_sha256": {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in sources},
        "inductive_obligations": len(positive), "nonvacuity_checks": len(positive),
        "negative_controls": len(negative_controls(state, heap)), "results": results,
        "claims": {
            "abstract_integer_ledger_event_invariants_inductive": passed,
            "guarded_scalar_return_balances_resource_counts": passed,
            "trap_or_quota_implies_cleanup": False,
            "production_runtime_refinement_proved": False,
            "per_owner_borrow_safety_proved": False,
            "machine_counter_overflow_proved": False,
            "whole_language_soundness_proved": False,
        },
        "limits": [
            "The theorem concerns a mathematical count model, not production Python/Rust/LLVM code.",
            "It excludes recursive-chain representation, pointers, alias/provenance rules, FFI, concurrency and asynchronous cancellation.",
            "Drop guards assume an admissible removed owner size and do not derive it from an object heap.",
            "Integer counters are unbounded; the production boundary separately enforces exact unsigned-u64 observations.",
            "Z3 and this small query generator are trusted; this is solver evidence, not a Lean-kernel proof or signed attestation.",
        ],
    }
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = check(args.output)
    print(json.dumps({key: report[key] for key in
        ("passed", "solver_version", "inductive_obligations", "nonvacuity_checks", "negative_controls")}, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
