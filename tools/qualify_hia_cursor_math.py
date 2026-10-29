#!/usr/bin/env python3
"""Check selected actual cursor helpers against a separate 66-bit math spec.

This proves index arithmetic under the trusted scalar encoders. It does not
prove pointer provenance, the C frontend, allocation validity or machine code.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.hia_program import verify_program  # noqa: E402
from hepta.hia_optimization import _fresh, _solver_identity  # noqa: E402
from hepta.hia_scalar_lowering_check import _reference, verify_scalar_lowering  # noqa: E402


def prove_cursor_math(program, *, function):
    import z3 as z

    checked = verify_program(program)
    document = checked.as_dict()
    fn = next(fn for fn in document["functions"] if fn["name"] == function)
    signature = [p["type"] for p in fn["params"]]
    if signature not in (["usize", "u64", "usize"], ["usize", "i64", "usize"]) or fn["returns"] != ["usize"]:
        raise ValueError("cursor spec requires (offset: usize, index: u64/i64, extent: usize) -> usize")
    # This also audits every reachable callee and CFG before symbolic expansion.
    lowering = verify_scalar_lowering(checked, function=function)
    if not lowering["verified"]:
        raise ValueError("selected actual LLVM lowering was not verified")
    context = z.Context()
    inputs = {p["name"]: _fresh(z, p["name"], p["type"], context) for p in fn["params"]}
    offset, index, extent = [value for value, _ in inputs.values()]
    signed = signature[1] == "i64"
    # 66 signed bits represent the full mathematical sum of a u64 offset
    # and either an i64 or u64 index without overflow. No input precondition
    # or observed sample narrows this specification.
    total = z.ZeroExt(2, offset) + (z.SignExt(2, index) if signed else z.ZeroExt(2, index))
    legal = z.And(total >= 0, total < z.ZeroExt(2, extent))
    expected = z.Extract(63, 0, total)
    returns, aborted, _ = _reference(z, context, fn, inputs, document)
    returned = z.Or(*[path for path, _ in returns]) if returns else z.BoolVal(False, ctx=context)
    mismatch = z.Or(aborted != z.Not(legal), returned != legal,
                    *[z.And(path, result != expected) for path, result in returns])
    solver = z.Solver(ctx=context)
    solver.set(timeout=5000)
    solver.add(mismatch)
    query = solver.sexpr()
    started = time.monotonic_ns()
    outcome = solver.check()
    wall = time.monotonic_ns() - started
    report = {"schema": "hepta.hia.cursor-math-check.v1", "function": function,
              "core_sha256": checked.sha256, "status": str(outcome), "verified": outcome == z.unsat,
              "signature": signature, "solver": _solver_identity(z), "solver_wall_ns": wall,
              "specification": "Return mathematical offset + index iff 0 <= offset + index < extent; otherwise abort.",
              "input_domain_bits": 192, "arithmetic_spec_width": 66, "input_preconditions": [],
              "query_sha256": sha256(query.encode()).hexdigest(), "smtlib": query,
              "math_checker_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
              "lowering": lowering,
              "claims": {"selected_core_index_bounds_for_all_typed_inputs": outcome == z.unsat,
                         "pointer_provenance_or_allocation_validity_proved": False,
                         "source_to_core_refinement_proved": False,
                         "native_backend_refinement_proved": False,
                         "whole_language_soundness_proved": False}}
    if outcome == z.sat:
        model = solver.model()
        report["counterexample"] = {name: str(model.eval(value, model_completion=True))
                                    for name, (value, _) in inputs.items()}
    elif outcome != z.unsat:
        report["reason"] = solver.reason_unknown()
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--function", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError("output must be new")
    report = prove_cursor_math(args.core.read_bytes(), function=args.function)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(json.dumps({key: report[key] for key in ("function", "verified", "status", "core_sha256", "solver_wall_ns")}))
    return 0 if report["verified"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
